#!/usr/bin/perl
package JKFlow;

use XML::Simple;
use Data::Dumper;
my (%mylist);

my $config=XMLin('./JKFlow.xml');

foreach my $router (keys %{$config->{routers}{router}}) {
	foreach my $application (keys %{$config->{routers}{router}{$router}{application}{service}}) {
		pushServices(
			$config->{routers}{router}{$router}{application}{service}{$application}{content},
			\%{$JKFlow::mylist{'router'}{$router}{'application'}{$application}});
	}
	pushServices(
		$config->{routers}{router}{$router}{services},
		\%{$JKFlow::mylist{'router'}{$router}{'service'}});
	pushProtocols(
		$config->{routers}{router}{$router}{protocols},
		\%{$JKFlow::mylist{'router'}{$router}{'protocol'}});
	if (defined $config->{routers}{router}{$router}{tos}) {
		$JKFlow::mylist{'router'}{$router}{tos}={};
	}
	if (defined $config->{routers}{router}{$router}{total}) {
		$JKFlow::mylist{'router'}{$router}{total}={};
	}
}

foreach my $subnet (keys %{$config->{subnets}{subnet}}) {
	foreach my $application (keys %{$config->{subnets}{subnet}{$subnet}{application}{service}}) {
		pushServices(
			$config->{subnets}{subnet}{$subnet}{application}{service}{$application}{content},
			\%{$JKFlow::mylist{'subnet'}{$subnet}{'application'}{$application}});
	}
	pushServices(
		$config->{subnets}{subnet}{$subnet}{services},
		\%{$JKFlow::mylist{'subnet'}{$subnet}{'service'}});
	pushProtocols(
		$config->{subnets}{subnet}{$subnet}{protocols},
		\%{$JKFlow::mylist{'subnet'}{$subnet}{'protocol'}});
	if (defined $config->{subnets}{subnet}{$subnet}{tos}) {
		$JKFlow::mylist{'subnet'}{$subnet}{tos}={};
	}
	if (defined $config->{subnets}{subnet}{$subnet}{total}) {
		$JKFlow::mylist{'subnet'}{$subnet}{total}={};
	}
}

foreach my $network (keys %{$config->{networks}{network}}) {
	foreach my $application (keys %{$config->{networks}{network}{$network}{application}{service}}) {
                $JKFlow::mylist{'network'}{$network}{'application'}{$application}{'fromsubnet'}=
			$config->{networks}{network}{$network}{application}{fromsubnet};
                $JKFlow::mylist{'network'}{$network}{'application'}{$application}{'tosubnet'}=
			$config->{networks}{network}{$network}{application}{tosubnet};
		pushServices(
			$config->{networks}{network}{$network}{application}{service}{$application}{content},
			\%{$JKFlow::mylist{'network'}{$network}{'application'}{$application}});
	}
	if (defined $config->{networks}{network}{$network}{routers}) {
		foreach my $router (split(/,/,$config->{networks}{network}{$network}{routers})) {
			$JKFlow::mylist{'network'}{$network}{'router'}{$router}={};
		}
	}
	if (defined $config->{networks}{network}{$network}{subnets}) {
		foreach my $subnet (split(/,/,$config->{networks}{network}{$network}{subnets})) {
			$JKFlow::mylist{'network'}{$network}{'subnet'}{$subnet}={};
		}
	}
}

print Dumper(%JKFlow::mylist);
exit;

sub pushProtocols {
my $refxml=shift;
my $ref=shift;
	foreach $proto (split(/,/,$refxml)) {
		if ($proto !~ /\d+/) { 
			$tmp = getprotobyname($proto) ||
				die "Unknown protocol $proto on line $.\n";
			$proto = $tmp;
		}
		$ref->{$proto} = {};
	}
}



sub pushServices {
my $refxml=shift;
my $ref=shift;
	foreach $current (split(/,/,$refxml)) {
		if ($current =~ /(\S+)\s*\/\s*(\S+)/) {
			$srv = $1;
			$proto = $2;
			if ($proto !~ /\d+/) { 
				$tmp = getprotobyname($proto) ||
					die "Unknown protocol $proto on line $.\n";
				$proto = $tmp;
			}
			if ($srv =~ /(\d+)-?(\d+)?/) {
				$start = $1;
				$end = (defined($2)) ? $2: $start;
				die "Bad range $start - $end on line $.\n" if
					($end < $start);
				for($i=$start;$i<=$end;$i++) {
					$ref->{$proto}{$i} = {};
				}
			} else {
				if ($srv !~ /\d+/) {
					$tmp = getservbyname($srv, getprotobynumber($proto)) || die "Unknown service $srv on line $.\n";
					$srv = $tmp;
				}
				$ref->{$proto}{$srv} = {};
			}
		} else {
			die "Bad Service Item $current on line $.\n";
		}	
	}
}
