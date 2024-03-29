#!/usr/bin/perl

use strict;
use warnings;

use IO::Select;
use IO::Socket;
use AlephLDAP;
use LDAPServerConfig;

my $config = LDAPServerConfig->load();

my $sock = IO::Socket::INET->new(
	Listen => 5,
	Proto => 'tcp',
	Reuse => 1,
	LocalPort => $config->{'server.port'}
);

my $sel = IO::Select->new($sock);
my %Handlers;
while (my @ready = $sel->can_read) {
	foreach my $fh (@ready) {
		if ($fh == $sock) {
			# let's create a new socket
			my $psock = $sock->accept;
			$sel->add($psock);
			$Handlers{*$psock} = AlephLDAP->new($psock);
		} else {
			my $result = $Handlers{*$fh}->handle;
			if ($result) {
				# we have finished with the socket
				$sel->remove($fh);
				$fh->close;
				delete $Handlers{*$fh};
			}
		}
	}
}

1;
