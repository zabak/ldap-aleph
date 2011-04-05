package AlephLDAP;

use strict;
use warnings;

use Data::Dumper;
use Date::Parse;
use Date::Language;
use LWP;
use LWP::UserAgent;
use URI::Escape;
use XML::Simple;
use Digest::MD5 qw(md5_hex md5_base64);
use Crypt::SmbHash qw(nthash);
use DBI;

use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_INVALID_CREDENTIALS);
use Net::LDAP::Filter;
use Net::LDAP::Server;
use base 'Net::LDAP::Server';
use fields qw();

use LDAPServerConfig;
my $config = LDAPServerConfig->load();

my $sambaDomainPrefix = "S-1-0-0";

my $base_query = "SELECT z308_rec_key AS rec_key, z308_verification AS pass, z308_id AS id, uuid AS uidNumber, entryUUID AS entryuuid
FROM pas00.z308 z308 LEFT OUTER JOIN pas00.uuids uuids ON z308.z308_id = uuids.id";

#helper functions
sub trim($) {
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

my $db = DBI->connect($config->{'db.url'}, $config->{'db.user'}, $config->{'db.password'});
my $db_attr = {};

sub new {
	my ($class, $sock) = @_;
	my $self = $class->SUPER::new($sock);
#	$self->{'ip'} = $sock->peerhost();
	printf "Accepted connection from: %s\n", $sock->peerhost();
	return $self;
}

sub debug {
	my $message = shift;
	open DEBUG, ">>", "debug.out";
	print DEBUG $message;
	close(DEBUG);
} 

sub ldap_code {
	my ($base, $code) = @_;
	return {
		'matchedDN' => $base,
		'errorMessage' => '',
		'resultCode' => $code
	};
}

# the bind operation
sub bind {
	my ($self, $req) = @_;
	my $name = $req->{'name'};
	my $base = "";
	if ($name=~/^uid=([0-9a-zA-Z]*),(.*)$/) {
		$name = $1;
		$base = $2;
	}
	my $pass = $req->{'authentication'}->{'simple'};
	if ($name eq "") {
		return ldap_code($base, LDAP_SUCCESS);
        } elsif (check_login($name, $pass)) {
		my $func = $config->{"dn:" . $base};
		my $person = aleph_xserver_query($name);
		if (defined($func) and $func->($config, $base, $person) == 0) {
 			return ldap_code($base, LDAP_INVALID_CREDENTIALS); #BAD_LOGIN;
		} else {
			return ldap_code($base, LDAP_SUCCESS);
		}
	} else {
		return ldap_code($base, LDAP_INVALID_CREDENTIALS);
	}
}

sub open_url {
	my $url = shift;
	my $ua = LWP::UserAgent->new;
	$ua->agent("MyApp/0.1 ");
	my $req = HTTP::Request->new(GET => $url);
	return $ua->request($req);
}

sub check_login {
	my ($user, $passwd) = @_;
	my $url = sprintf('http://%s/X?op=bor_auth&bor_id=%s&verification=%s&library=%s', $config->{'aleph.host'}, $user, $passwd, $config->{'aleph.adm_lib'});
	my $res = open_url($url);	
	my $ref = XML::Simple::XMLin($res->content);
	return ($ref->{error})?0:1;
}

# the search operation
sub search {
	my $self = shift;
	my $req = shift;
	my @entries;
	my $base = $req->{'baseObject'};
	if ($base=~/^uid=([0-9a-zA-Z_]*),(.*)$/) {
		$req->{"filter"} = {
			'and' => [
				{'equalityMatch' => {
					'assertionValue' => $1,
					'attributeDesc' => 'employeeNumber'
				}},
				$req->{"filter"}		
			]
		}
	};
	my ($query, @values) = to_sql($req->{"filter"});
	my $results = execute_query($base, $query, @values);
	foreach my $result (@$results) {
#		next if ($result->{"VALID"} == 0 and $base eq "ou=readers,dc=mzk,dc=cz");
		my $func = $config->{"dn:" . $base};
		my $valid = 0;
		my %properties;
		if (defined($func)) {
			($valid, %properties) = $func->($config, $base, $result);
			next if ($valid == 0);
		}
		my $entry = Net::LDAP::Entry->new;
		$entry->dn("uid=" . $result->{"NICK"} . "," . $base); # $result->{"RC"} # $result->{"NICK"} # $result->{"BARCODE"}
		$entry->add(
			objectclass => "top",
			objectclass => "person",
			objectclass => "organizationalPerson",
			objectclass => "inetOrgPerson",
			objectclass => "posixAccount",
                        objectclass => "sambaSamAccount",
			objectclass => "apple-user",
                        userpassword => $result->{"USERPASSWORD"},
                        sambaNTPassword => $result->{"SAMBAPASSWORD"},
                        sambaAcctFlags => "[U          ]",
			uidNumber => $result->{"UIDNUMBER"},
                        sambaSID => $result->{"SAMBASID"},
			gidNumber => 5001,
			homeDirectory => "/srv/home/" . $result->{"UIDNUMBER"},
			loginShell => "/bin/bash",
			description => "reader",
			uid => $result->{"NICK"}, # uid => $result->{"RC"}, # uid => $result->{"NICK"} # uid => $result->{"BARCODE"}
			mail => $result->{"EMAIL"},
			cn => $result->{"NAME"},
			gecos => $result->{"NAME"},
			nick => $result->{"NICK"},
			employeeNumber => $result->{"BARCODE"},
			organizationalUnit => "readers",
			group => "readers",
			departmentNumber => "readers",
			entryUUID => $result->{"ENTRYUUID"}
		);
		while (my ($key, $value) = each %properties) {
			$entry->add($key => $value);
		}
		push (@entries, $entry);
	}
	return return ldap_code($base, LDAP_SUCCESS), @entries;
}

sub to_sql {
	my $query = shift;
	my @values = ();
	($query, @values) = transform($query, @values);
	my $limit = 10;
 	$query = "$base_query WHERE ($query) AND z308_verification IS NOT NULL AND rownum <= $limit";
	return ($query, @values);
}

sub transform {
	# my $filter = shift;
	my ($filter, @values) = @_;
	my @ops = ("or", "and");
	foreach my $op (@ops) {
		if (defined $filter->{$op}) {
			my $result = "(";
			my $exp = $filter->{$op};
			my $sep = "";
			foreach my $cond (@$exp) {
				my @temp_values = ();
				my $temp_query = "";
				($temp_query, @temp_values) = transform($cond, @temp_values);
				$result.= $sep . $temp_query;
				foreach my $temp_value (@temp_values) {
					push(@values, $temp_value);
				}
				$sep = " " . uc($op) . " ";
			}
			$result .= ")";
			return ($result, @values);
		}
	}
 	if (defined $filter->{"equalityMatch"}) {
		my $cond = $filter->{"equalityMatch"};
		my $key = $cond->{"attributeDesc"};
		my $value = $cond->{"assertionValue"};
		if (lc($key) eq "employeenumber" || lc($key) eq "uid") {
			my $value1 = sprintf("%-27s", uc("01" . $value));
			my $value2 = sprintf("%-27s", uc("02" . $value));
			push(@values, $value1);
			push(@values, $value2);
			return ("(z308_rec_key = ? OR z308_rec_key=?)", @values);
		} elsif (lc($key) eq "objectclass" and lc($value) ne "group" and lc($value) ne "mount") {
			return " 1 = 1";
		} elsif (lc($key) eq "uidnumber") {
			push(@values, $value);
			return ("(uuid = ?)", @values);
		} elsif (lc($key) eq "entryuuid") {
			push(@values, $value);
			return ("(entryuuid = ?)", @values);	
                } elsif (lc($key) eq "sambasid" and $value =~/(S-[0-9]+-[0-9]+-[0-9]+)-([0-9]+)/) {
                        my $uid = $2;
                        if ($1 eq $sambaDomainPrefix) {
				push(@values, $uid);
				return ("(uuid = ?)", @values);
                        } else {
                                return " 1 = 0 ";
                        }
                } else {
			print "$key = $value not matched!\n";
		}
	}
	return (" 1 = 1 ", @values) if (defined $filter->{"present"});
	return (" 1 = 0 ", @values);
}

sub entryUUID {
	my $data = shift;
	my $salt = "MZK_ALEPH_LDAP";
	my $hash = Digest::MD5::md5_hex($salt . $data);
	return substr($hash, 0, 8) . "-" . substr($hash, 8, 4) . "-" .  substr($hash, 12, 4) . "-" . substr($hash, 16, 4) . "-" . substr($hash, 20, 12);
}

sub add_user {
	my $person = shift;
	my $rc = $person->{"RC"};
	my $entryUUID = entryUUID($rc);
	my $insert = "INSERT INTO pas00.uuids(id, uuid, entryuuid) VALUES (?, pas00.uids.nextval, ?)";
	my $result = $db->do($insert, $db_attr, ($rc, $entryUUID)) or die $db->errstr;
	my $sth = $db->prepare("SELECT id, uuid, entryuuid FROM pas00.uuids WHERE id = ?");
	$sth->execute(sprintf("%-12s", $rc));
	$result = $sth->fetchrow_hashref();
	print Dumper($result);
	$person->{"ID"} = $result->{"ID"};
	$person->{"UIDNUMBER"} = $result->{"UUID"};
	$person->{"ENTRYUUID"} = $result->{"ENTRYUUID"};
	return $person;
}

sub execute_query {
	my ($base, $query, @values) = @_;
	print "$query @values\n";
#	my $query = shift;
	my $start_time = time();
	my @result;
        my %seen = ();
	my $sth = $db->prepare($query);
	$sth->execute(@values);
	while (my $result = $sth->fetchrow_hashref()) {
		print "got result\n";
		my $id = $result->{"ID"};
		if ($seen{$id} or substr($result->{"REC_KEY"}, 0, 2) eq "00") {
			next;
		}
		$seen{$id} = 1;
		my $pass = uc($result->{"PASS"});
		my $person = aleph_xserver_query($id);
		$person->{"ID"} = $id;
		$person->{"USERPASSWORD"} = "{CRYPT}" . crypt(lc($pass), "lp");
                $person->{"SAMBAPASSWORD"} = nthash(lc($pass)); 
		$person->{"NICK"} = trim(substr($result->{"REC_KEY"}, 2));
		if (not defined $result->{"UIDNUMBER"}) {
			$person = add_user($person);
		} else {
			$person->{"UIDNUMBER"} = $result->{"UIDNUMBER"};
			$person->{"ENTRYUUID"} = $result->{"ENTRYUUID"};
		}
                $person->{"SAMBASID"} = $sambaDomainPrefix . "-" . $person->{"UIDNUMBER"}; #sambaSID
		push(@result, $person)
	}
	my $end_time = time();
	my $time = ($end_time - $start_time);
	debug("Execution time: $time seconds\n"); 
	return \@result;
}

sub aleph_xserver_query {
	my $user = shift;
	$user = URI::Escape::uri_escape($user);
	my $url = sprintf('http://%s/X?op=bor-info&bor-id=%s&user_name=%s&user_password=%s&library=%s&cash=B&hold=N&loans=N',
		$config->{'aleph.host'}, $user, $config->{'aleph.user'}, $config->{'aleph.password'}, $config->{'aleph.adm_lib'});
	my $res = open_url($url);
	my $start_time = time();
	my $ref = XML::Simple::XMLin($res->content);
	die "Error occured while executing X server service: " . $ref->{error} if ($ref->{error});
	my $rc = $ref->{"z303"}->{"z303-id"};
	my $id = scalar($ref->{"z304"}[0]->{"z304-address-0"});
	my $name = scalar($ref->{"z303"}->{"z303-name"});
	my $email = scalar($ref->{"z304"}[0]->{"z304-email-address"});
	$email = '' if (ref($email) eq "HASH");
	my $end_time = time();
	my $time = ($end_time - $start_time);
	debug("X-server execution time: $time seconds\n");
	return { "RC" => "$rc",  "ID" => $id, "EMAIL" => $email, "NAME" => $name, "BARCODE" => $id };
}

1;

