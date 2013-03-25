package LDAPServerConfig;

sub load {
	# my %hash = ();
	my %config = ();
	# port on which ldap server is running
	$config{'server.port'} = 8000;
	$config{'db.url'} = 'dbi:Oracle:host=zeus;SID=aleph20;';
	$config{'db.user'} = 'db.user';
	$config{'db.password'} = 'db.password';
	$config{'ldap.base_dn'} = 'dc=mzk,dc=cz';
	$config{'aleph.host'} = 'aleph.mzk.cz';
	$config{'aleph.user'} = 'aleph.user';
	$config{'aleph.password'} = 'aleph.password';
	$config{'aleph.adm_lib'} = 'MZK50';
	$config{'dn:ou=shibboleth,dc=mzk,dc=cz'} = \&shibboleth_filter,
	$config{'dn:ou=readers,dc=mzk,dc=cz'} = \&readers_filter,
	return \%config;
}

sub trim($) {
        my $string = shift;
        $string =~ s/^\s+//;
        $string =~ s/\s+$//;
        return $string;
}

sub shibboleth_filter {
	my ($config, $dn, $user) = @_;
	print "ou=shibboleth,dc=mzk,dc=cz\n";
	return 1;
}

sub readers_filter {
	my ($config, $dn, $user) = @_;
	my $valid = 1;
	# registration finished
	my $delinq1 = scalar($ref->{"z303"}->{"z303-delinq-1"});
	if ($delinq1 eq "50") {
		$valid = 0;
	}
	# has no debt
	my $balance = $ref->{"balance"};
	my $sign = $ref->{"sign"};
	if (defined($balance) and $sign eq "D" and $balance > 0) {
		$valid = 0;
	}
	# user account is not expired
	my $valid_until = scalar($ref->{"z305"}->{"z305-expiry-date"});        
	if (defined($valid_until)) {
		my $lang = Date::Language->new('English');
		$valid_until = $lang->str2time($valid_until);
		my $now = time() - 86400;
		if ($now > $valid_until) {
			$valid = 0;
		}
	}
	$result{"apple-user-homeDirectory"} = "/Network/Servers/severus.mzk.cz/srv/home/" . $result->{"UIDNUMBER"},
  $result{"aleph-id"} = trim($user->{"ID"});
	return ($valid, %result);
}

return 1;
