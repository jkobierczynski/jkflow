#!/usr/bin/perl 

# ----------------- JKFlow.pm ----------------------

# A flexible, scalable reporting module for FlowScan
# It is very versatile in configuration, which is done
# by in a XML, named JKFlow.xml
  
# JKFlow.pm has started as modification of CUFlow,
# but has become a complete rewrite in which all good
# elements of CUFlow were kept, but many new things are
# added.

 
# It is intended to be a replacement for SubnetIO.pm
# and functionality of SubnetIO.pm, in more configurable
# fashion. 
# Owes *VERY* heavily to Dave Plonka's SubnetIO.pm and CampusIO.pm
# Thanks, Dave :) <plonka@doit.wisc.edu>

# To Add:
# ICMP type handling as a Service, ie 6/icmp Echo
# Make Networks record services? How, while still being fast?

#use strict;
use Data::Dumper;

package JKFlow;

require 5;
require Exporter;

@JKFlow::ISA=qw(FlowScan Exporter);

# convert the RCS revision to a reasonable Exporter VERSION:
'$Revision$ ' =~ m/(\d+)\.(\d+)/ && (( $JKFlow::VERSION ) = sprintf("%d.%03d", $1, $2));

=head1 NAME

JKFlow - XML configurable flowscan reporting module.

=head1 SYNOPSIS

   $ flowscan JKFlow

or in F<flowscan.cf>:

   ReportClasses JKFlow

=head1 DESCRIPTION

JKFlow.pm creates rrds matching the configuration given in JKFlow.xml. 
It allows you to create classes in which you can select any number of
router exporters, any number of subnets, any network of grouping of
router exporters/subnets, all router exporters, all subnets or simply
anything in which you can monitor for any protocol/service or application
,which is a grouping of services, type-of-services, broadcasts, or the
total network traffic. You can define 'directions' which selects  
source subnets and a destination subnets, wherein you can define several
other monitoring capabilities and other directions.

=head1 CONFIGURATION

JKFlow's configuration file is F<JKFlow.xml>. This configuration file is
located in the directory in which the F<flowscan> script resides.

=over 4

=item A

=back

=cut

use Cflow qw(:flowvars 1.015);  # for use in wanted sub
use RRDs;			# To actually produce results
use Socket;			# We need inet_aton
use Net::Patricia;		# Fast IP/mask lookups
use POSIX;			# We need floor()
use FindBin;			# To find our executable
use XML::Simple;
use HTML::Table;

my(%ROUTERS);			# A hash mapping exporter IP's to the name
				# we want them to be called, e.g.
				# $ROUTER{"127.0.0.1"} = 'localhost';
my($SUBNETS);			# A trie of the subnets that are 'inside'
my(%SERVICES);			# A hashtable containing services we are
				# interested in. E.g.:
				# $SERVICES{'www'} = { 80 => { 6 } }
				# means that we are interested in www/tcp
				# and that it has label 'www'
my($RRDDIR) = '.';		# The directory we will stow rrd files in
my($SCOREDIR) = '.';		# The directory we will stow rrd files in

$JKFlow::SCOREKEEP = 10;        # The top N addresses to report on. By default
				# don't keep scoreboards.

my($scorepage) = 'index.html';	# The link to the current page

my($aggscorekeep) = 0;		# Do not create an overall rankings file

$JKFlow::NUMKEEP = 50;		# How many aggregates to keep

my(%myservices);
my(%myalllist);
my($subnet);
my($config);

my($flowrate) = 1;

$JKFlow::multicast = 0;		# Do multicast? Default no.

# Multicast address spec's, taken from CampusIO
$JKFlow::MCAST_NET  = unpack('N', inet_aton('224.0.0.0'));
$JKFlow::MCAST_MASK = unpack('N', inet_aton('240.0.0.0'));

$JKFlow::SUBNETS = new Net::Patricia || die "Could not create a trie ($!)\n";
$JKFlow::fromtrie = new Net::Patricia || die "Could not create a trie ($!)\n";
$JKFlow::totrie = new Net::Patricia || die "Could not create a trie ($!)\n";
&parseConfig;	# Read our config file

sub parseConfig {
    my($ip,$mask,$srv,$proto,$label,$tmp,$txt);
    my($num,$dir,$current,$start,$end,$i,$subnet,$router,$networkname);

	use XML::Simple;
	$config=XMLin('/usr/local/bin/JKFlow.xml',
#		keyattr => { router => 'exporter'},
		forcearray=>[	'router','routergroup','interface','subnet','site','network',
				'direction','application','defineset','set']);

	$JKFlow::RRDDIR = $config->{rrddir};
	$JKFlow::SCOREDIR = $config->{scoredir};

	if (defined $config->{all}) {
		if (defined $config->{'all'}{'localsubnets'}) {
			$JKFlow::mylist{'all'}{'localsubnets'}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$config->{all}{'localsubnets'})) {
				print "All: + localsubnets subnet $subnet\n";
				$JKFlow::mylist{'all'}{'localsubnets'}->add_string($subnet);
			}
		}
		if (defined $config->{all}{samplerate}) {
			$JKFlow::mylist{all}{samplerate}=$config->{all}{samplerate};
		} else {
			$JKFlow::mylist{all}{samplerate}=1;
		}
		parseDirection (
			\%{$config->{all}},
			\%{$JKFlow::mylist{all}});
	}

	#use Data::Dumper;

	if (defined $config->{routergroups}) {
		if (defined $config->{routergroups}{routergroup}){
			foreach my $routergroup (keys %{$config->{routergroups}{routergroup}}) {
				print "Routergroup: $routergroup\n";
				foreach my $exporter (@{$config->{routergroups}{routergroup}{$routergroup}{router}}) {
					print "Exporter: ".$exporter->{exporter}.", ";
					$JKFlow::mylist{routers}{router}{$exporter->{exporter}}=$routergroup;
					if (defined $exporter->{interface}) {
						print "interface: ".$exporter->{interface};
						$JKFlow::mylist{routers}{router}{$exporter->{exporter}}{$exporter->{interface}}=$routergroup;
					} elsif (defined $exporter->{localsubnets}) {
						print "localsubnets: ".$exporter->{localsubnets};
						$JKFlow::mylist{routers}{router}{$exporter->{exporter}}{localsubnets}=new Net::Patricia || die "Could not create a trie ($!)\n";
						foreach my $localsubnet (split (/,/,$exporter->{localsubnets})) {
							$JKFlow::mylist{routers}{router}{$exporter->{exporter}}{localsubnets}->add_string($localsubnet);
						}
					}
					print "\n";
				}
			}
		}
	}	

	#foreach my $routername (keys %{$config->{routers}{router}}) {
	#	print "Routers: + router $routername\n";
	#	if (defined $config->{routers}{router}{$routername}{localsubnets}) {
	#		$JKFlow::mylist{routers}{router}{$routername}{localsubnets}=new Net::Patricia || die "Could not create a trie ($!)\n";
	#		foreach my $subnet (split(/,/,$config->{routers}{router}{$routername}{localsubnets})) {
	#			print "Routers: router $routername + localsubnets subnet $subnet\n";
	#			$JKFlow::mylist{routers}{router}{$routername}{localsubnets}->add_string($subnet);
	#		}
	#	}
	#	foreach my $router (split(/,/,$config->{routers}{router}{$routername}{routers})) {
	#		print "Routers: router $routername + routerip $router\n";
	#		$JKFlow::mylist{'router'}{$routername}{'routers'}{$router}={};
	#	}
	#	if (defined $config->{routers}{router}{$routername}{interface}) {
	#		foreach my $interfacecode (keys %{$config->{routers}{router}{$routername}{interface}}) {
	#			print "Routers: router $routername + interface $interfacecode\n";
	#			if (defined $config->{routers}{router}{$routername}{interface}{$interfacecode}{description}) {
	#				$JKFlow::mylist{'router'}{$routername}{interface}{$interfacecode}{description}=$config->{routers}{router}{$routername}{interface}{$interfacecode}{description};
	#			}
	#			if (defined $config->{routers}{router}{$routername}{interface}{$interfacecode}{samplerate}) {
	#				$JKFlow::mylist{'router'}{$routername}{interface}{$interfacecode}{samplerate}=$config->{'router'}{$routername}{interface}{$interfacecode}{samplerate};
	#			} else {
	#				$JKFlow::mylist{'router'}{$routername}{interface}{$interfacecode}{samplerate}=1;
	#			}
	#			parseDirection (
	#				\%{$config->{routers}{router}{$routername}{interface}{$interfacecode}},
	#				\%{$JKFlow::mylist{router}{$routername}{interface}{$interfacecode}});
	#		}
	#	}
	#
	#	if (defined $config->{routers}{router}{$routername}{samplerate}) {
	#		$JKFlow::mylist{router}{$routername}{samplerate}=$config->{routers}{router}{$routername}{samplerate};
	#	} else {
	#		$JKFlow::mylist{router}{$routername}{samplerate}=1;
	#	}
	#	parseDirection (
	#		\%{$config->{routers}{router}{$routername}},
	#		\%{$JKFlow::mylist{router}{$routername}});
	#		
	#}

	pushDirections (
		\%{$config->{directions}{direction}},
		\%{$JKFlow::mylist{direction}});


	foreach my $network (keys %{$config->{networks}{network}}) {
		if (defined $config->{netwerks}{network}{$network}{direction}) { 
			$JKFlow::mylist{'netwerk'}{$network}{'direction'}={};
			pushDirections(
				$config->{networks}{network}{$network}{direction},
				\%{$JKFlow::mylist{'network'}{$network}{'direction'}});
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

	pushDirections3( \@{$JKFlow::mylist{'fromsubnets'}}, $JKFlow::fromtrie );
	pushDirections3( \@{$JKFlow::mylist{'tosubnets'}}, $JKFlow::totrie );
	
	if (defined $config->{router}{total_router}) {
		$JKFlow::mylist{'total_router'} = {};
	}	
	#use Data::Dumper;
	#print Dumper($JKFlow::mylist{routergroup});
	#print Dumper($JKFlow::mylist{direction});
}

sub parseDirection {
my $refxml=shift;
my $ref=shift;

		pushServices(
			$refxml->{services},
			\%{$ref->{service}});
		pushProtocols(
			$refxml->{protocols},
			\%{$ref->{protocol}});
		if (defined $refxml->{direction}) { 
			$ref->{direction}={};
			pushDirections(
				$refxml->{direction},
				\%{$ref->{direction}});

		}
		if (defined $refxml->{application}) { 
			$ref->{application}={};
			pushApplications( 
				$refxml->{application},
				\%{$ref->{application}});
		}
		if (defined $refxml->{ftp}) {
			$ref->{ftp}={};
		}
		if (defined $refxml->{multicast}) {
			$ref->{multicast}={};
		}
		if (defined $refxml->{tos}) {
			$ref->{tos}={};
		}
		if (defined $refxml->{total}) {
			$ref->{total}={};
		}
		if (defined $refxml->{scoreboard}) {
			if (defined $refxml->{scoreboard}{hosts} && $refxml->{scoreboard}{hosts}=="1") {
				$ref->{scoreboard}{hosts}={};
			}
			if (defined $refxml->{scoreboard}{ports} && $refxml->{scoreboard}{ports}=="1") {
				$ref->{scoreboard}{ports}={};
			}
		}
		if (defined $refxml->{write}) {
			$ref->{write}=$refxml->{write};
 		} else {
			$ref->{write}="yes";
		}
		if (defined $refxml->{set}) {
			foreach my $set (keys %{$refxml->{set}}) {
				print "parseDirection: ".$set."\n";
				parseDirection(
					\%{$config->{definesets}{defineset}{$set}},
					$ref);
			}
		}
}

sub pushProtocols {
my $refxml=shift;
my $ref=shift;
my $tmp;

	foreach my $proto (split(/,/,$refxml)) {
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
my ($srv,$proto,$start,$end,$tmp,$i);

	foreach my $current (split(/,/,$refxml)) {
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

sub pushApplications {
my $refxml=shift;
my $ref=shift;
my ($srv,$proto,$start,$end,$tmp,$i);
	foreach my $application (keys %{$refxml}) {
		foreach my $current (split(/,/,$refxml->{$application}{'content'})) {
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
						$ref->{$application}{'service'}{$proto}{$i} = {};
					}
				} else {
					if ($srv !~ /\d+/) {
						$tmp = getservbyname($srv, getprotobynumber($proto)) || die "Unknown service $srv on line $.\n";
						$srv = $tmp;
					}
					$ref->{$application}{'service'}{$proto}{$srv} = {};
				}
			} else {
				die "Bad Service Item $current on line $.\n";
			}
		}	
	}
}

sub pushDirections {
my $refxml=shift;
my $ref=shift;
my ($srv,$proto,$start,$end,$tmp,$i);

	foreach my $direction (keys %{$refxml}) {
		print "Adding direction $direction\n";
		my $fromsubnets=[];
		my $tosubnets=[];
		my $nofromsubnets=[];
		my $notosubnets=[];
		$ref->{$direction}{name}=$direction;

		if (defined $refxml->{$direction}{'samplerate'}) {
			$ref->{$direction}{'samplerate'}=$refxml->{$direction}{'samplerate'};
		} else {
			$ref->{$direction}{'samplerate'}=1;
		}
		
		if (defined $refxml->{$direction}{'fromsubnets'}) {
			${$ref->{$direction}{'fromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'fromsubnets'})) {
				print "Adding fromsubnets subnet $subnet \n";
				push @{$fromsubnets}, $subnet;
				push @{$JKFlow::mylist{fromsubnets}}, { subnet=>$subnet, type=>'included' };
				${$ref->{$direction}{'fromsubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'tosubnets'}) { 
			${$ref->{$direction}{'tosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'tosubnets'})) {
				print "Adding tosubnets subnet $subnet \n";
				push @{$tosubnets}, $subnet;
				push @{$JKFlow::mylist{tosubnets}}, { subnet=>$subnet, type=>'included' };
				${$ref->{$direction}{'tosubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'nofromsubnets'}) {
			${$ref->{$direction}{'nofromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'nofromsubnets'})) {
				print "Adding nofromsubnets subnet $subnet \n";
				push @{$nofromsubnets}, $subnet;
				push @{$JKFlow::mylist{fromsubnets}}, { subnet=>$subnet, type=>'excluded' };
				${$ref->{$direction}{'nofromsubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'notosubnets'}) { 
			${$ref->{$direction}{'notosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'notosubnets'})) {
				print "Adding notosubnets subnet $subnet \n";
				push @{$notosubnets}, $subnet;
				push @{$JKFlow::mylist{tosubnets}}, { subnet=>$subnet, type=>'excluded' };
				${$ref->{$direction}{'notosubnets'}}->add_string($subnet);
			}
		}

		if (defined $refxml->{$direction}{"from"}) {
			if (!defined $ref->{$direction}{'fromsubnets'}) {
				${$ref->{$direction}{'fromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			}
			if (!defined $ref->{$direction}{'nofromsubnets'}) {
				${$ref->{$direction}{'nofromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			}
			print "Adding fromsubnets ".$refxml->{$direction}{"from"}."\n";
			foreach my $site (split(/,/,$refxml->{$direction}{'from'})) {
				print "Adding fromsite $site \n";
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{subnets})) {
					print "Adding fromsubnets subnet $subnet \n";
					push @{$fromsubnets}, $subnet;
					push @{$JKFlow::mylist{fromsubnets}}, { subnet=>$subnet, type=>'included' };
					${$ref->{$direction}{'fromsubnets'}}->add_string($subnet);
				}
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{nosubnets})) {
					print "Adding nofromsubnets subnet $subnet \n";
					push @{$nofromsubnets}, $subnet;
					push @{$JKFlow::mylist{fromsubnets}}, { subnet=>$subnet, type=>'excluded' };
					${$ref->{$direction}{'nofromsubnets'}}->add_string($subnet);
				}	
			}
		}

		if (defined $refxml->{$direction}{"to"}) {
			if (!defined $ref->{$direction}{'tosubnets'}) {
				${$ref->{$direction}{'tosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			}
			if (!defined $ref->{$direction}{'notosubnets'}) {
				${$ref->{$direction}{'notosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			}
			print "Adding tosubnets ".$refxml->{$direction}{"to"}."\n";
			foreach my $site (split(/,/,$refxml->{$direction}{'to'})) {
				print "Adding tosite $site \n";
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{subnets})) {
					print "Adding tosubnets subnet $subnet \n";
					push @{$tosubnets}, $subnet;
					push @{$JKFlow::mylist{tosubnets}}, { subnet=>$subnet, type=>'included' };
					${$ref->{$direction}{'tosubnets'}}->add_string($subnet);
				}
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{nosubnets})) {
					print "Adding notosubnets subnet $subnet \n";
					push @{$notosubnets}, $subnet;
					push @{$JKFlow::mylist{tosubnets}}, { subnet=>$subnet, type=>'excluded' };
					${$ref->{$direction}{'notosubnets'}}->add_string($subnet);
				}	
			}
		}

		foreach my $fromsubnet (@{$fromsubnets}) {
			foreach my $tosubnet (@{$tosubnets}) {
				print "Subnets: FROM=".$fromsubnet." TO=".$tosubnet."\n";
				my $list=[];
				if (defined $JKFlow::mylist{subnets}{$fromsubnet}{$tosubnet}) {
					$list=$JKFlow::mylist{subnets}{$fromsubnet}{$tosubnet};
				}
				push @{$list},{ 
				nofromsubnets=>$nofromsubnets,
				notosubnets=>$notosubnets,
				ref=>$ref->{$direction}
				};
				$JKFlow::mylist{subnets}{$fromsubnet}{$tosubnet}=$list;
			}
		}

		if ($refxml->{$direction}{'monitor'} eq 'yes') {
			$ref->{$direction}{monitor}="Yes";
		} else {
			$ref->{$direction}{monitor}="No";
		}
		parseDirection (
			\%{$refxml->{$direction}},
			\%{$ref->{$direction}});
		
		if (defined $refxml->{$direction}{"routergroup"}) {
			print "push direction to routergroup\n";
			if (defined $JKFlow::mylist{routergroup}{$refxml->{$direction}{"routergroup"}}) {
				die "You can assign routergroup ".$refxml->{$direction}{"routergroup"}." only once!\n";
			}
			print "Assign routergroup ".$refxml->{$direction}{"routergroup"}." to ".$direction."\n";
			$JKFlow::mylist{routergroup}{$refxml->{$direction}{"routergroup"}}=\%{$ref->{$direction}};
		}

	}
}

sub pushDirections3 {
my $subnetlist=shift;
my $ref=shift;
my %seen=();

	@sortedlist = 
	sort {
		my @c=split /\//, $a->{subnet};
		my @d=split /\//, $b->{subnet};
		$c[1] <=> $d[1];
		}  @{$subnetlist};

	@sortedlist = grep {! $seen{$_->{subnet}.$_->{type}}++ } @sortedlist;

	foreach my $addsubnet (@sortedlist) {
		my %seen = ();
		my $includedlist = [];
		my $excludedlist = [];
		if (defined $ref->match_string($addsubnet->{subnet})) {
			push @{$includedlist}, @{${$ref->match_string($addsubnet->{subnet})}{included}};
			push @{$excludedlist}, @{${$ref->match_string($addsubnet->{subnet})}{excluded}};
		}
		if ($addsubnet->{type} eq 'included') {
			@{$includedlist} = grep { ! $seen{$_} ++ } ( @{$includedlist}, $addsubnet->{subnet} );
		} else {
			@{$excludedlist} = grep { ! $seen{$_} ++ } ( @{$excludedlist}, $addsubnet->{subnet} );
		}
		$ref->add_string($addsubnet->{subnet},{included=>$includedlist,excluded=>$excludedlist});
	}
}



sub new {
   my $self = {};
   my $class = shift;
  
   return bless _init($self), $class
}

sub _init {
   my $self = shift;
  
   return $self
}

# This is called once per flow record, more than 800k times per file. It
# needs to be as fast and as short as possible.
sub wanted {
    my $self = shift;
    my $which;

	# Counting ALL
	if (defined $JKFlow::mylist{'all'}) {
		$which = 'out';
		if (defined $JKFlow::mylist{'all'}{'localsubnets'}) {
			if ($JKFlow::mylist{'all'}{'localsubnets'}->match_integer($dstaddr)) {
				$which = 'in';
			} 
		}
		countpackets(\%{$JKFlow::mylist{'all'}},$which);
		countApplications(\%{$JKFlow::mylist{'all'}{'application'}},$which);
		#countDirections(\%{$JKFlow::mylist{'all'}{'direction'}},$which);

	}
	#print "Exporter:".$exporterip." Interface:".$output_if."\n";

	# Counting for Routers
	if (defined $JKFlow::mylist{routers}{router}{$exporterip}) {
		my $routergroup = $JKFlow::mylist{routers}{router}{$exporterip};
		if (defined $JKFlow::mylist{routers}{router}{$exporterip}{$output_if}) {
			#use Data::Dumper;
			#print Dumper(%{$JKFlow::mylist{routergroup}{$routergroup}})."\n";
				countpackets(\%{$JKFlow::mylist{routergroup}{$routergroup}},'out');
				countApplications(\%{$JKFlow::mylist{routergroup}{$routergroup}{'application'}},'out');
		}
		if (defined $JKFlow::mylist{routers}{router}{$exporterip}{$input_if}) {
			#use Data::Dumper;
			#print Dumper(%{$JKFlow::mylist{routergroup}{$routergroup}})."\n";
				countpackets(\%{$JKFlow::mylist{routergroup}{$routergroup}},'in');
				countApplications(\%{$JKFlow::mylist{routergroup}{$routergroup}{'application'}},'in');
		} 
		if (defined $JKFlow::mylist{routers}{router}{$exporterip}{localsubnets}) {
			#use Data::Dumper;
			#print Dumper(%{$JKFlow::mylist{routergroup}{$routergroup}})."\n";
			$which = 'out';
			if ($JKFlow::mylist{routers}{router}{$exporterip}{localsubnets}->match_integer($dstaddr)) {
				$which = 'in';
			}
				countpackets(\%{$JKFlow::mylist{routergroup}{$routergroup}},$which);
				countApplications(\%{$JKFlow::mylist{routergroup}{$routergroup}{'application'}},$which);
		}
	}

	# Counting for specific Routers
	#foreach my $routername (keys %{$JKFlow::mylist{'router'}}) {
	#	$which = 'out';
	#	if (defined $JKFlow::mylist{'router'}{$routername}{'localsubnets'}) {
	#		if ($JKFlow::mylist{'router'}{$routername}{'localsubnets'}->match_integer($dstaddr)) {
	#			$which = 'in';
	#		} 
	#	}
	#	if (defined $JKFlow::mylist{'router'}{$routername}{'routers'}{$exporterip}) {
	#		#Added Interfaces monitoring
	#		if ( defined $JKFlow::mylist{'router'}{$routername}{'interface'}{$output_if}) {
	#			countpackets(\%{$JKFlow::mylist{'router'}{$routername}{'interface'}{$output_if}},'out');
	#			countApplications(\%{$JKFlow::mylist{'router'}{$routername}{'interface'}{$output_if}{'application'}},'out');
	#			#countDirections(\%{$JKFlow::mylist{'router'}{$routername}{'interface'}{$output_if}{'direction'}},'out');
	#		} 
	#		if ( defined $JKFlow::mylist{'router'}{$routername}{'interface'}{$input_if}) {
	#			countpackets(\%{$JKFlow::mylist{'router'}{$routername}{'interface'}{$input_if}},'in');
	#			countApplications(\%{$JKFlow::mylist{'router'}{$routername}{'interface'}{$input_if}{'application'}},'in');
	#			#countDirections(\%{$JKFlow::mylist{'router'}{$routername}{'interface'}{$input_if}{'direction'}},'in');
	#		}
	#		countpackets(\%{$JKFlow::mylist{'router'}{$routername}},$which);
	#		countApplications(\%{$JKFlow::mylist{'router'}{$routername}{'application'}},$which);
	#		#countDirections(\%{$JKFlow::mylist{'router'}{$routername}{'direction'}},$which);
	#	}
	#}
	countDirections2();

    return 1;
}

sub countDirections {
my $ref=shift;
my $which=shift;

	foreach my $direction (keys %{$ref}) {
		if ( (!defined $ref->{$direction}{'tosubnets'} || ($dstsubnet=${$ref->{$direction}{'tosubnets'}}->match_integer($dstaddr)))
		&&  (!defined $ref->{$direction}{'fromsubnets'} || ($srcsubnet=${$ref->{$direction}{'fromsubnets'}}->match_integer($srcaddr))) 
		&&  (!defined $ref->{$direction}{'notosubnets'} || (!${$ref->{$direction}{'notosubnets'}}->match_integer($dstaddr))) 
		&&  (!defined $ref->{$direction}{'nofromsubnets'} || (!${$ref->{$direction}{'nofromsubnets'}}->match_integer($srcaddr))) )
		{
				if ($ref->{$direction}{monitor} eq "Yes") {
					print "D1 SRC = ".inet_ntoa(pack(N,$srcaddr)).", SRCSUBNET = $srcsubnet, DST = ".inet_ntoa(pack(N,$dstaddr)).", DSTSUBNET = $dstsubnet \n"; 
				}
				#print "tosubnet".${$ref->{$direction}{'tosubnets'}}->match_integer($dstaddr).",";
				#print "fromsubnet".${$ref->{$direction}{'fromsubnets'}}->match_integer($srcaddr)."\n";
    				#use Data::Dumper;
    				#print Dumper(%{$ref->{$direction}})."\n";
	 			#countpackets (\%{$ref->{$direction}},'out');
				#countApplications(\%{$ref->{$direction}{'application'}},'out');
		}
		elsif ( (!defined $ref->{$direction}{'fromsubnets'} || ($dstsubnet=${$ref->{$direction}{'fromsubnets'}}->match_integer($dstaddr)))
		&&  (!defined $ref->{$direction}{'tosubnets'} || ($srcsubnet=${$ref->{$direction}{'tosubnets'}}->match_integer($srcaddr)))
		&&  (!defined $ref->{$direction}{'nofromsubnets'} || (!${$ref->{$direction}{'nofromsubnets'}}->match_integer($dstaddr)))
		&&  (!defined $ref->{$direction}{'notosubnets'} || (!${$ref->{$direction}{'notosubnets'}}->match_integer($srcaddr))) ) 
		{
				if ($ref->{$direction}{monitor} eq "Yes") {
					print "D1 DST = ".inet_ntoa(pack(N,$dstaddr)).", DSTSUBNET = $dstsubnet, SRC = ".inet_ntoa(pack(N,$srcaddr)).", SRCSUBNET = $srcsubnet \n"; 
				}
				#print "tosubnet".${$ref->{$direction}{'tosubnets'}}->match_integer($dstaddr).",";
				#print "fromsubnet".${$ref->{$direction}{'fromsubnets'}}->match_integer($srcaddr)."\n";
    				#use Data::Dumper;
    				#print Dumper(%{$ref->{$direction}})."\n";
	 			#countpackets (\%{$ref->{$direction}},'in');
				#countApplications(\%{$ref->{$direction}{application}},'in');
		}
		countDirections(\%{$ref->{$direction}{'direction'}},$which);
	}
}

sub countDirections2 {

	my $srcsubnets;
	my $dstsubnets;
	
	my $fromtriematch = $JKFlow::fromtrie->match_integer($srcaddr);
	my $totriematch = $JKFlow::totrie->match_integer($dstaddr);

	if ((defined $fromtriematch) && (defined ($srcsubnets = $fromtriematch->{included}))) {
		if ((defined $totriematch) && (defined ($dstsubnets = $totriematch->{included}))) {
			foreach my $srcsubnet (@{$srcsubnets}) {
				foreach my $dstsubnet (@{$dstsubnets}) {
					#print "SrcSubnet=".$srcsubnet."\n";
					#print "DstSubnet=".$dstsubnet."\n";
					if (defined $JKFlow::mylist{subnets}{$srcsubnet}{$dstsubnet}) {
						foreach $direction (@{$JKFlow::mylist{subnets}{$srcsubnet}{$dstsubnet}}) {
							my %i={},%j={};
							if (	
							(! grep { ++$i{$_} > 1 } ( @{$fromtriematch->{excluded}},@{$direction->{nofromsubnets}})) && 
							(! grep { ++$j{$_} > 1 } ( @{$totriematch->{excluded}},@{$direction->{notosubnets}}))) {
								if ($direction->{ref}{monitor} eq "Yes") {
									print "D2 SRC = ".inet_ntoa(pack(N,$srcaddr)).", SRCSUBNET = $srcsubnet, DST = ".inet_ntoa(pack(N,$dstaddr)).", DSTSUBNET = ".$dstsubnet."\n"; 
								}
								countpackets (\%{$direction->{ref}},'out');
								countApplications (\%{$direction->{ref}{application}},'out');
							}
						}
					}
				}
			}
		}
	}

	$fromtriematch = $JKFlow::fromtrie->match_integer($dstaddr);
	$totriematch = $JKFlow::totrie->match_integer($srcaddr);
        
	if ((defined $fromtriematch) && (defined ($dstsubnets = $fromtriematch->{included}))) {
        	if ((defined $totriematch) && (defined ($srcsubnets = $totriematch->{included}))) {
        		foreach my $dstsubnet (@{$dstsubnets}) {
                		foreach my $srcsubnet (@{$srcsubnets}) {
					#print "DstSubnet=".$dstsubnet."\n";
					#print "SrcSubnet=".$srcsubnet."\n";
					if (defined $JKFlow::mylist{subnets}{$dstsubnet}{$srcsubnet}) {
						foreach $direction (@{$JKFlow::mylist{subnets}{$dstsubnet}{$srcsubnet}}) {
							my %i={},%j={};
							if (
							(! grep { ++$i{$_} > 1 } ( @{$fromtriematch->{excluded}},@{$direction->{nofromsubnets}})) && 
							(! grep { ++$j{$_} > 1 } ( @{$totriematch->{excluded}},@{$direction->{notosubnets}}))) {
								if ($direction->{ref}{monitor} eq "Yes") {
									print "D2 DST = ".inet_ntoa(pack(N,$dstaddr)).", DSTSUBNET = $dstsubnet, SRC = ".inet_ntoa(pack(N,$srcaddr)).", SRCSUBNET = ".$srcsubnet.", EXPORTER = ".$exporter. "\n"; 
								}
                        					countpackets (\%{$direction->{ref}},'in');
                        					countApplications (\%{$direction->{ref}{application}},'in');
							}
						}
					}
				}
			}
                }
        }
}

sub countApplications {
    	my $ref = shift;
    	my $which = shift;
    	my $typeos;
	foreach my $application (keys %{$ref}) {
		if (		(defined $ref->{$application}{'service'}) 
			&& 	(defined $ref->{$application}{'service'}{$protocol})) {
			if (defined $ref->{$application}{'service'}{$protocol}{$dstport}) {
				$ref->{$application}{'dst'}{$which}{'flows'}++;
				$ref->{$application}{'dst'}{$which}{'bytes'} += $bytes;
				$ref->{$application}{'dst'}{$which}{'pkts'} += $pkts;
			}
			elsif (defined $ref->{$application}{'service'}{$protocol}{$srcport}) {
				$ref->{$application}{'src'}{$which}{'flows'}++;
				$ref->{$application}{'src'}{$which}{'bytes'} += $bytes;
				$ref->{$application}{'src'}{$which}{'pkts'} += $pkts;
			}
		}
	}
}

sub countpackets {
    	my $ref = shift;
    	my $which = shift;
    	my $typeos;
	if (defined $ref->{'total'}) {
		$ref->{'total'}{$which}{'flows'} ++;
		$ref->{'total'}{$which}{'bytes'} += $bytes;
		$ref->{'total'}{$which}{'pkts'} += $pkts;
	}
	if ($tos == 0) {
		$typeos="normal";
    	} else {
       		$typeos="other"; 
    	}
	if (defined $ref->{'tos'}) {
    		$ref->{'tos'}{$typeos}{$which}{'flows'} ++;
		$ref->{'tos'}{$typeos}{$which}{'bytes'} += $bytes;
		$ref->{'tos'}{$typeos}{$which}{'pkts'} += $pkts;
	}
	if (defined $ref->{'multicast'} && 
		(($dstaddr & $JKFlow::MCAST_MASK) == $JKFlow::MCAST_NET)) {
		$ref->{'multicast'}{'total'}{$which}{'flows'}++;
		$ref->{'multicast'}{'total'}{$which}{'bytes'} += $bytes;
		$ref->{'multicast'}{'total'}{$which}{'pkts'} += $pkts;
	}
	if ((defined $ref->{'protocol'}) && (defined $ref->{'protocol'}{$protocol})) {
      		$ref->{'protocol'}{$protocol}{'total'}{$which}{'flows'}++;
		$ref->{'protocol'}{$protocol}{'total'}{$which}{'bytes'} += $bytes;
		$ref->{'protocol'}{$protocol}{'total'}{$which}{'pkts'} += $pkts;
	}
	if ((defined $ref->{'service'}) && (defined $ref->{'service'}{$protocol})) {
		if (defined $ref->{'service'}{$protocol}{$dstport}) {
			$ref->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'flows'}++;
			$ref->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'bytes'} += $bytes;
			$ref->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'pkts'} += $pkts;
		}
		elsif (defined $ref->{'service'}{$protocol}{$srcport}) {
			$ref->{'service'}{$protocol}{$srcport}{'src'}{$which}{'flows'}++;
			$ref->{'service'}{$protocol}{$srcport}{'src'}{$which}{'bytes'} += $bytes;
			$ref->{'service'}{$protocol}{$srcport}{'src'}{$which}{'pkts'} += $pkts;
		}
	}
	if (defined $ref->{'ftp'}) {
       		countftp(\%{$ref->{'ftp'}},$which);
	}
	if (defined $ref->{'scoreboard'}) {
		if (defined $ref->{'scoreboard'}{hosts}) {
			$ref->{'scoreboard'}{hosts}{'dst'}{'flows'}{$dstip}{$which} ++;
			$ref->{'scoreboard'}{hosts}{'dst'}{'bytes'}{$dstip}{$which} += $bytes;
			$ref->{'scoreboard'}{hosts}{'dst'}{'pkts'}{$dstip}{$which} += $pkts;
			$ref->{'scoreboard'}{hosts}{'src'}{'flows'}{$srcip}{$which} ++;
			$ref->{'scoreboard'}{hosts}{'src'}{'bytes'}{$srcip}{$which} += $bytes;
			$ref->{'scoreboard'}{hosts}{'src'}{'pkts'}{$srcip}{$which} += $pkts;
		}
		if (defined $ref->{'scoreboard'}{ports}) {
			$ref->{'scoreboard'}{ports}{'dst'}{'flows'}{$dstport}{$which} ++;
			$ref->{'scoreboard'}{ports}{'dst'}{'bytes'}{$dstport}{$which} += $bytes;
			$ref->{'scoreboard'}{ports}{'dst'}{'pkts'}{$dstport}{$which} += $pkts;
			$ref->{'scoreboard'}{ports}{'src'}{'flows'}{$srcport}{$which} ++;
			$ref->{'scoreboard'}{ports}{'src'}{'bytes'}{$srcport}{$which} += $bytes;
			$ref->{'scoreboard'}{ports}{'src'}{'pkts'}{$srcport}{$which} += $pkts;
		}
	}
}

sub countftp {
	my $ref = shift;
	my $which = shift;
	if (	($srcport == 21) || ($dstport == 21) 
		|| ($srcport == 20) || ($dstport == 20) 
		|| (($srcport >= 1024) && ($dstport >= 1024))) {
		if ( 	(($srcport >= 1024) && ($dstport >=1024))
			|| ($srcport == 20) || ($dstport == 20)	) {
			if ( defined $ref->{cache}{"$dstaddr:$srcaddr"} ) {
				$ref->{'dst'}{$which}{'flows'}++;
				$ref->{'dst'}{$which}{'bytes'} += $bytes;
				$ref->{'dst'}{$which}{'pkts'} += $pkts;
				#if (($srcport == 20) || ($dstport == 20)) {
				#	print "Active FTP session $which: $srcaddr -> $dstaddr $bytes bytes\n";
				#} else {
				#	print "Passive FTP session $which: $srcaddr -> $dstaddr $bytes bytes\n";
				#}	
				$ref->{cache}{"$dstaddr:$srcaddr"} = $endtime;
			} elsif ( defined $ref->{cache}{"$srcaddr:$dstaddr"} ) {
				$ref->{'src'}{$which}{'flows'}++;
				$ref->{'src'}{$which}{'bytes'} += $bytes;
				$ref->{'src'}{$which}{'pkts'} += $pkts;
				#if (($srcport == 20) || ($dstport == 20)) {
				#	print "Active FTP session $which: $srcaddr -> $dstaddr $bytes bytes\n";
				#} else {
				#	print "Passive FTP session $which: $srcaddr -> $dstaddr $bytes bytes\n";
				#}	
				$ref->{cache}{"$srcaddr:$dstaddr"} = $endtime;
			} 
		} elsif ($dstport == 21) {
			$ref->{'dst'}{$which}{'flows'}++;
			$ref->{'dst'}{$which}{'bytes'} += $bytes;
			$ref->{'dst'}{$which}{'pkts'} += $pkts;
			if (!defined $ref->{cache}{"$dstaddr:$srcaddr"}) {
				$ref->{cache}{"$dstaddr:$srcaddr"}=$endtime;
			}
		} elsif ($srcport == 21) {
			$ref->{'src'}{$which}{'flows'}++;
			$ref->{'src'}{$which}{'bytes'} += $bytes;
			$ref->{'src'}{$which}{'pkts'} += $pkts;
			if (!defined $ref->{cache}{"$srcaddr:$dstaddr"}) {
				$ref->{cache}{"$srcaddr:$dstaddr"}=$endtime;
			}
		}	
	}
}

sub perfile {
    # Only do this, so we get the filetime from our super-class
    my $self = shift;

    $JKFlow::totals = ();	# Clear this out

    $self->SUPER::perfile(@_);
}

sub summarize {
   my $sumref = shift;
   my $addref = shift;
   my $samplerate = shift;
   my $typeos;

   foreach my $type ('bytes','pkts','flows') {
      foreach my $which ('in','out') {
		if (defined $addref->{'protocol'}) {
			foreach my $protocol (keys %{$addref->{'protocol'}}) { 
				$sumref->{'protocol'}{$protocol}{'total'}{$which}{$type} 
					+= $addref->{'protocol'}{$protocol}{'total'}{$which}{$type}*$samplerate;
			}
		}

		if (defined $addref->{'service'}) {
			foreach my $protocol (keys %{$addref->{'service'}}) { 
				foreach my $service (keys %{$addref->{'service'}{$protocol}}) {
					$sumref->{'service'}{$protocol}{$service}{'src'}{$which}{$type} 
						+= $addref->{'service'}{$protocol}{$service}{'src'}{$which}{$type}*$samplerate;
					$sumref->{'service'}{$protocol}{$service}{'dst'}{$which}{$type} 
						+= $addref->{'service'}{$protocol}{$service}{'dst'}{$which}{$type}*$samplerate;
				}
			}
		}

		if (defined $addref->{'multicast'}) {
         		$sumref->{'multicast'}{'total'}{$which}{$type} 
				+= $addref->{'multicast'}{'total'}{$which}{$type}*$samplerate;
		}
		if (defined $addref->{'tos'}) {
			foreach my $typeos ('normal','other') {
			$sumref->{'tos'}{$typeos}{$which}{$type}
				+= $addref->{'tos'}{$typeos}{$which}{$type}*$samplerate;
			}
		}
		if (defined $addref->{'total'}) {
			$sumref->{'total'}{$which}{$type} 
				+= $addref->{'total'}{$which}{$type}*$samplerate;
		}
      }
   }
}   

sub reporttorrd {

 	use RRDs;			# To actually produce results
	my $self=shift;
	my $file=shift;
	my $ref=shift;
	my $samplerate=shift;
	my $tmp;
	my @values = ();

	# First, always generate a totals report
	# createGeneralRRD we get from our parent, FlowScan
	# Create a new rrd if one doesn't exist
	$self->createGeneralRRD($file,
			    qw(
			       ABSOLUTE in_bytes
			       ABSOLUTE out_bytes
			       ABSOLUTE in_pkts
			       ABSOLUTE out_pkts
			       ABSOLUTE in_flows
			       ABSOLUTE out_flows
			       )
			    ) unless -f $file; 

	foreach my $i ('bytes','pkts','flows') {
		foreach my $j ('in','out') {
			if (!(defined($tmp = $ref->{$j}{$i}))) {
				push(@values, 0);
			} else {
				push(@values, $tmp * $samplerate);
				$ref->{$j}{$i}=0;
			}
		}
	}
	$self->updateRRD($file, @values);
	print "File: $file @values\n";
}

sub reporttorrdfiles {

	use RRDs;
	my $self=shift;
	my $dir=shift;
	my $ref=shift;
	my $samplerate=shift;
	my ($file,$tmp);

	# First, always generate a totals report
	# createGeneralRRD we get from our parent, FlowScan
 	# Create a new rrd if one doesn't exist
	if (defined $ref->{'total'}) {	
		$file = $JKFlow::RRDDIR . $dir . "/total.rrd";
		reporttorrd($self,$file,\%{$ref->{'total'}},$samplerate);
	}

	if (defined $ref->{'tos'}) {	
		foreach my $tos ('normal','other') {
			$file = $JKFlow::RRDDIR . $dir . "/tos_". $tos . ".rrd";
			reporttorrd($self,$file,\%{$ref->{'tos'}{$tos}},$samplerate);
 		}
	}

	if (defined $ref->{'multicast'}) {	
		$file = $JKFlow::RRDDIR . $dir . "/protocol_multicast.rrd";
		reporttorrd($self,$file,\%{$ref->{'multicast'}{'total'}},$samplerate);
	}

	if (defined $ref->{'protocol'}) {	
		foreach my $protocol (keys %{$ref->{'protocol'}}) {
			if (!($tmp = getprotobynumber($protocol))) {
				$tmp = $protocol;
			}
			$file = $JKFlow::RRDDIR. $dir . "/protocol_" . $tmp . ".rrd";
			reporttorrd($self,$file,\%{$ref->{'protocol'}{$protocol}{'total'}},$samplerate);
		}
	}

	if (defined $ref->{'service'}) {	
		foreach my $src ('src','dst') {
			foreach my $protocol (keys %{$ref->{'service'}}) {
				foreach my $srv (keys %{$ref->{'service'}{$protocol}}) {
					if (!($tmp = getservbyport ($srv, getprotobynumber($protocol)))) {
						$tmp = $srv;
					}
					$file = $JKFlow::RRDDIR. $dir . "/service_" . getprotobynumber($protocol). "_". $tmp . "_" . $src . ".rrd";
					reporttorrd($self,$file,\%{$ref->{'service'}{$protocol}{$srv}{$src}},$samplerate);
				}
			}
		}
	}

	if (defined $ref->{'application'}) {	
		foreach my $src ('src','dst') { 
			foreach my $application (keys %{$ref->{'application'}}) {
  	     			$file = $JKFlow::RRDDIR. $dir . "/service_" . $application . "_" . $src . ".rrd";
				reporttorrd($self,$file,\%{$ref->{'application'}{$application}{$src}},$samplerate);
			}
		}
	}

	if (defined $ref->{'ftp'}) {	
		foreach my $src ('src','dst') { 
  	     		$file = $JKFlow::RRDDIR. $dir . "/service_ftp_" . $src . ".rrd";
			reporttorrd($self,$file,\%{$ref->{'ftp'}{$src}},$samplerate);
		}
		foreach my $pair (keys %{$ref->{'ftp'}{cache}}) {
			if ($self->{filetime}-$ref->{'ftp'}{cache}{$pair} > 2*60*60 ||
			    $self->{filetime}-$ref->{'ftp'}{cache}{$pair} < -15 * 60 ) {
				#print "Deleted FTP-session: $pair Timediff:".($self->{filetime}-$ref->{'ftp'}{cache}{$pair})."\n";	
				delete($ref->{'ftp'}{cache}{$pair});
			}
		}
	}

	if (defined $ref->{'scoreboard'}) {
		scoreboard($self, \%{$ref->{'scoreboard'}}, $dir . "/" . $direction);
	}

	if (defined $ref->{'direction'}) {
		foreach my $direction (keys %{$ref->{'direction'}}) {
			if (! -d $JKFlow::RRDDIR . $dir."/".$direction ) {
				mkdir($JKFlow::RRDDIR . $dir . "/" . $direction ,0755);
			}
			if (! -d $JKFlow::SCOREDIR . $dir."/".$direction ) {
				mkdir($JKFlow::SCOREDIR . $dir . "/" . $direction ,0755);
			}	
			reporttorrdfiles($self, $dir . "/" . $direction, \%{$ref->{'direction'}{$direction}},$ref->{'direction'}{$direction}{'samplerate'});
		}
	}
}

sub report {
	my $self = shift;
	my($file) = $JKFlow::RRDDIR . "/total.rrd";
	my($routerfile);
	my(@values) = ();
	my(@array);
	my($count, $i ,$j ,$k , $tmp,$srv,$rt,$sn, $subnetdir,$routerdir);
	my $interf_name;

	#use Data::Dumper;
	#print Dumper($JKFlow::mylist{routergroup});

	#if (defined $JKFlow::mylist{'total_router'}) {
	#	foreach my $router (keys %{$JKFlow::mylist{'router'}}) {
	#		summarize(\%{$JKFlow::mylist{'total_router'}},\%{$JKFlow::mylist{'router'}{$router}},$JKFlow::mylist{'router'}{$router}{'samplerate'});
	#	}
	#}

	#foreach my $network (keys %{$JKFlow::mylist{'network'}}) {
 	#	foreach my $router (keys %{$JKFlow::mylist{'network'}{$network}{'router'}}) {
	#		print "Summarize $network, $router \n";
	#		summarize(\%{$JKFlow::mylist{'network'}{$network}},\%{$JKFlow::mylist{'router'}{$router}},$JKFlow::mylist{'router'}{$router}{'samplerate'});
	#	}
	#}  
	
	if (${$JKFlow::mylist{'all'}}{'write'} eq 'yes') {
		if (! -d $JKFlow::RRDDIR."/all" ) {
			mkdir($JKFlow::RRDDIR."/all",0755);
		}
		if (! -d $JKFlow::SCOREDIR."/all" ) {
			mkdir($JKFlow::SCOREDIR."/all",0755);
		}
		reporttorrdfiles($self,"/all",\%{$JKFlow::mylist{'all'}},$JKFlow::mylist{'all'}{'samplerate'});
		if (defined $JKFlow::mylist{'all'}{scoreboard}) {
			scoreboard($self, \%{$JKFlow::mylist{'all'}{scoreboard}}, "/all");
		}
	}

	#if (! -d $JKFlow::RRDDIR."/total_router" ) {
	#	mkdir($JKFlow::RRDDIR."/total_router",0755);
	#}
	#reporttorrdfiles($self,"/total_router",\%{$JKFlow::mylist{'total_router'}},1);

	#foreach my $router (keys %{$JKFlow::mylist{'router'}}) {
	#	if (${$JKFlow::mylist{'router'}{$router}}{'write'} eq 'yes') {
	#		print "Router:$router\n";
	#		if (! -d $JKFlow::RRDDIR . "/router_$router" ) {
	#			mkdir($JKFlow::RRDDIR . "/router_$router",0755);
	#		}
	#		if (! -d $JKFlow::SCOREDIR . "/router_$router" ) {
	#			mkdir($JKFlow::SCOREDIR . "/router_$router",0755);
	#		}
	#		reporttorrdfiles($self,"/router_".$router,\%{$JKFlow::mylist{'router'}{$router}},$JKFlow::mylist{'router'}{$router}{'samplerate'});
	#		if (defined $JKFlow::mylist{'router'}{$router}{scoreboard}) { 
	#			scoreboard($self, \%{$JKFlow::mylist{'router'}{$router}{scoreboard}}, "/router_".$router);
	#		}
	#		
	#	}
	#	if (defined $JKFlow::mylist{'router'}{$router}{'interface'}) {
	#		foreach my $interface (keys %{$JKFlow::mylist{'router'}{$router}{'interface'}}) {
	#		#use Data::Dumper;
	#		#print "INTERFACES:".Dumper($JKFlow::mylist{'router'}{$router}{'interface'})."\n";
	#			if (defined $JKFlow::mylist{'router'}{$router}{'interface'}{$interface}{description}) {
	#				$interf_name = ${$JKFlow::mylist{'router'}{$router}{'interface'}{$interface}}{description};
	#				if (! -d $JKFlow::RRDDIR."/router_$router/$interf_name" ) {
	#					mkdir($JKFlow::RRDDIR."/router_$router/$interf_name",0755);
	#				}
	#				if (! -d $JKFlow::SCOREDIR."/router_$router/$interf_name" ) {
	#					mkdir($JKFlow::SCOREDIR."/router_$router/$interf_name",0755);
	#				}
	#				reporttorrdfiles($self,"/router_".$router."/".$interf_name,\%{$JKFlow::mylist{'router'}{$router}{'interface'}{$interface}},$JKFlow::mylist{'router'}{$router}{'interface'}{$interface}{'samplerate'});
	#			} else {
	#				if (! -d $JKFlow::RRDDIR."/router_$router/interface_$interface" ) {
	#					mkdir($JKFlow::RRDDIR."/router_$router/interface_$interface", 0755);
	#				}
	#				if (! -d $JKFlow::SCOREDIR."/router_$router/interface_$interface" ) {
	#					mkdir($JKFlow::SCOREDIR."/router_$router/interface_$interface", 0755);
	#				}
	#				reporttorrdfiles($self,"/router_".$router."/interface_".$interface,\%{$JKFlow::mylist{'router'}{$router}{'interface'}{$interface}},$JKFlow::mylist{'router'}{$router}{'interface'}{$interface}{'samplerate'});
	#			}
	#			if (defined $JKFlow::mylist{'router'}{$router}{'interface'}{$interface}{scoreboard}) {
	#				scoreboard($self, \%{$JKFlow::mylist{'router'}{$router}{'interface'}{$interface}{scoreboard}}, "/router_".$router);
	#			}
	#		}
	#	}
	#}

	foreach my $direction (keys %{$JKFlow::mylist{'direction'}}) {
		print "Reporting Direction $direction \n";
		if (! -d $JKFlow::RRDDIR . $dir."/".$direction ) {
			mkdir($JKFlow::RRDDIR . $dir . "/" . $direction ,0755);
		}
		if (! -d $JKFlow::SCOREDIR . $dir."/".$direction ) {
			mkdir($JKFlow::SCOREDIR . $dir . "/" . $direction ,0755);
		}	
		#reporttorrdfiles($self, $dir . "/" . $direction, \%{$JKFlow::mylist{'direction'}{$direction}},$JKFlow::mylist->{'direction'}{$direction}{'samplerate'});
		reporttorrdfiles($self, $dir . "/" . $direction, \%{$JKFlow::mylist{'direction'}{$direction}},1);
	}
    
	#foreach my $network (keys %{$JKFlow::mylist{'network'}}) {
	#	if (! -d $JKFlow::RRDDIR."/network_".$network ) {
	#		mkdir($JKFlow::RRDDIR."/network_".$network,0755);
	#	}
	#	if (! -d $JKFlow::SCOREDIR."/network_".$network ) {
	#		mkdir($JKFlow::SCOREDIR."/network_".$network,0755);
	#	}
	#	reporttorrdfiles($self,"/network_".$network,\%{$JKFlow::mylist{'network'}{$network}},1);
	#	if (defined $JKFlow::mylist{'network'}{$network}{scoreboard}) {
	#		scoreboard($self, \%{$JKFlow::mylist{'network'}{$network}{scoreboard}}, "/network_".$network);
	#	}
	#}
}

# Lifted totally and shamelessly from CampusIO.pm
# I think perhaps this goes into FlowScan.pm, but...
sub updateRRD {
   my $self = shift;
   my $file = shift;
   my @values = @_;

   RRDs::update($file, $self->{filetime} . ':' . join(':', @values));
   my $err=RRDs::error;
   warn "ERROR updating $file: $err\n" if ($err);
}

# Function to read in the current aggregate data
# Returns a hash of ip to (count of times in top ten, ttl bytes in,
#			   ttl pkts in, ttl flows in, ttl bytes out,
#			   ttl pkts out, ttl flows out
sub readAggFile
{
    my $dir=shift;
    my($ip,$cnt,$bin,$pin,$fin,$bout,$pout,$fout);
    my(%ret) = ();

    if (-f $dir.$JKFlow::aggscorefile) {	# Exists, try reading it in
	open(AGG,$dir.$JKFlow::aggscorefile) ||
	    die "Cannot open $dir.$JKFlow::aggscorefile ($!)\n";
	$ret{'numresults'} = <AGG>;
	chomp($ret{'numresults'});
	while(<AGG>) {
	    if (
		($ip,$cnt,$bin,$pin,$fin,$bout,$pout,$fout) =
	(/(\d+\.\d+\.\d+\.\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)/))
	    {
		# Skip any data that has rolled over
		if (($cnt < 0) || ($bin < 0) || ($bout < 0) ||
		    ($pin < 0) || ($pout < 0) || ($fin < 0) ||
		    ($fout < 0)) {
		    print STDERR "Rollover for $ip\n";
		    next;	# Skip it
		}

		$ret{$ip} = { 'count'    => $cnt,
			      'bytesin'  => $bin,
			      'bytesout' => $bout,
			      'pktsin'   => $pin, 
			      'pktsout'  => $pout,
			      'flowsin'  => $fin,
			      'flowsout' => $fout };
	    }
	}
	close AGG;
    }
    return %ret;
}

# Function to write the aggregate data out to a file
sub writeAggFile (\%)
{
    my %data = %{(shift)};
    my $dir = shift;
    
    open(OUT,">$dir.$JKFlow::aggscorefile") ||
	die "Cannot open $dir.$JKFlow::aggscorefile for write ($!)\n";

    print OUT $data{'numresults'} . "\n";
    foreach my $ip (keys %data) {
	next if ($ip =~ /numresults/);
	printf OUT "%s %d %d %d %d %d %d %d\n",
			$ip,
			$data{$ip}->{'count'},
			$data{$ip}->{'bytesin'},
			$data{$ip}->{'pktsin'},
			$data{$ip}->{'flowsin'},
			$data{$ip}->{'bytesout'},
			$data{$ip}->{'pktsout'},
			$data{$ip}->{'flowsout'};
    }

    close OUT;
}

# Function to print the pretty table of over-all winners
sub writeAggScoreboard (\%)
{
    my %data = %{(shift)};
    my $dir = shift;
    my($key, $i);
    my(@sorted);
    my(%dnscache);
    my($tmp) = $data{'numresults'};

    delete $data{'numresults'};

    open(OUT,">$dir.$JKFlow::aggscoreout") ||
	die "Cannot open $dir.$JKFlow::aggscoreout for write ($!)\n";

    print OUT "<html>\n<body bgcolor=\"\#ffffff\">\n\n<center>\n";
    print OUT "<h3> Average rankings for the last $tmp topN reports\n<hr>\n";
    print OUT "</center>\n";

    # Now, print out our 6 topN tables
    my %columns = ('bytes' => 3, 'pkts' => 5, 'flows' => 7);

    foreach my $dir ('in','out') {
	foreach my $key ('bytes','pkts','flows') {
	    @sorted = sort { ($data{$b}->{"$key$dir"} / 
			      $data{$b}->{'count'})
				 <=> 
			     ($data{$a}->{"$key$dir"} /
			      $data{$a}->{'count'}) }
	    	(keys %data);

	    my $table = new 'HTML::Table';
	    die unless ref($table);    

	    $table->setBorder(1);
	    $table->setCellSpacing(0);
	    $table->setCellPadding(3);

	    $table->setCaption("Top $JKFlow::aggscorekeep by " .
			       "<b>$key $dir</b><br>\n" .
			       "built on aggregated topN " .
			       "5 minute average samples to date",
			       'TOP');

	    my $row = 1;
	    $table->addRow('<b>rank</b>',
			   "<b>$dir Address</b>",
			   '<b>bits/sec in</b>',
			   '<b>bits/sec out</b>',
			   '<b>pkts/sec in</b>',
			   '<b>pkts/sec out</b>',
			   '<b>flows/sec in</b>',
			   '<b>flows/sec out</b>');
	    $table->setRowBGColor($row, '#FFFFCC'); # pale yellow

	    # Highlight the current column (out is 1 off from in)
	    $table->setCellBGColor($row, $columns{$key} + ('out' eq $dir),
				   '#90ee90'); # light green
	    $row++;	    
	    for($i=0;$i < @sorted; $i++) {
		last unless $i < $JKFlow::aggscorekeep;
		my $ip = $sorted[$i];

		if (!(defined($dnscache{$ip}))) { # No name here?
		    if ($dnscache{$ip} = gethostbyaddr(pack("C4", 
							split(/\./, $ip)),
						       AF_INET)) {
			$dnscache{$ip} .= "<br>$ip (" .
			    $data{$ip}->{'count'} . " samples)";
		    } else {
			$dnscache{$ip} = $ip . " (" .
			    $data{$ip}->{'count'} . " samples)";
		    }
		}

		my $div = 300 * $data{$ip}->{'count'};
		$table->addRow( sprintf("#%d",$i+1),
				$dnscache{$ip},      # IP Name/Address
				
				# Bits/sec in
				scale("%.1f", ($data{$ip}->{'bytesin'}*8) /
				                $div),
				
				# Bits/sec out
				scale("%.1f", ($data{$ip}->{'bytesout'}*8) /
				                $div),

				# Pkts/sec in
				scale("%.1f", ($data{$ip}->{'pktsin'}/$div)),

				# Pkts/sec out
				scale("%.1f", ($data{$ip}->{'pktsout'}/$div)),
				
				# Flows/sec in
				scale("%.1f", ($data{$ip}->{'flowsin'}/$div)),

				# Flows/sec out
				scale("%.1f",
				      ($data{$ip}->{'flowsout'}/$div)));

		
		$table->setRowAlign($row, 'RIGHT');
		$table->setCellBGColor($row,
				       $columns{$key} + ('out' eq $dir),
				       '#add8e6'); # light blue
		$row++;
	    }
	    print OUT "<p>\n$table</p>\n\n";
	}
    }
    
    close OUT;
    $data{'numresults'} = $tmp;
}

# Handle writing our HTML scoreboard reports
sub scoreboard {    
	my $self = shift;
	my $ref = shift;
	my $dir = shift;

	my($i,$file,$item,$hr);
	my (@values, @sorted);
	my(%dnscache) = ();
	my(%aggdata, %newaggdata);

	# First, should we read in the aggregate data?
	if ($JKFlow::aggscorekeep > 0) {
		%aggdata = &readAggFile($dir);
	}

	# Next, open the file, making any necessary directories
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
		localtime($self->{filetime});  

	$mon++; $year += 1900;

	foreach my $type ('hosts','ports') { 

		next if (! defined $ref->{$type});

		$file=sprintf("%s/%s/%s",$JKFlow::SCOREDIR,$dir,$type);

 		if (! -d $file) {
			mkdir($file,0755) || die "Cannot mkdir $file ($!)\n";
		}

		$file=sprintf("%s/%s/%s/%4.4d-%2.2d-%2.2d",$JKFlow::SCOREDIR,$dir,$type,$year,$mon,$mday);

 		if (! -d $file) {
			mkdir($file,0755) || die "Cannot mkdir $file ($!)\n";
		}

 		$file = sprintf("%s/%2.2d",$file,$hour);
		if (! -d $file) {
			mkdir($file,0755) || die "Cannot mkdir $file ($!)\n";
		}
    
		$file = sprintf("%s/%2.2d:%2.2d:%2.2d.html",$file,$hour,$min,$sec);
		open(HTML,">$file") || die "Could not write to $file ($!)\n";

		# Now, print out our header stuff into the file
 		print HTML "<html>\n<body bgcolor=\"\#ffffff\">\n<center>\n\n";

		# Now, print out our 6 topN tables
		my %columns = ('bytes' => 3, 'pkts' => 5, 'flows' => 7);

		foreach my $srcdst ('src','dst') {
			@values = ();

			foreach my $key ('bytes','pkts','flows') {

				foreach my $direction ('in', 'out') {

					@sorted = sort {$ref->{$type}{$srcdst}{$key}{$b}{$direction} <=> $ref->{$type}{$srcdst}{$key}{$a}{$direction}} (keys %{$ref->{$type}{$srcdst}{$key}});
	    
					# This part lifted totally from CampusIO.pm. Thanks, dave!
					my $table = new HTML::Table;
					die unless ref($table);
					$table->setBorder(1);
					$table->setCellSpacing(0);
					$table->setCellPadding(3);
	
					$table->setCaption("Top $JKFlow::scorekeep by " .
						"<b>$key $srcdst $direction</b><br>\n" .
						"for five minute flow sample ending " .
						scalar(localtime($self->{filetime})),
						'TOP');

					my $row = 1;
					$table->addRow('<b>rank</b>',
						"<b>$srcdst Address</b>",
						'<b>bits/sec in</b>',
						'<b>bits/sec out</b>',
						'<b>pkts/sec in</b>',
						'<b>pkts/sec out</b>',
						'<b>flows/sec in</b>',
						'<b>flows/sec out</b>');

					$table->setRowBGColor($row, '#FFFFCC'); # pale yellow

					# Highlight the current column (out is 1 off from in)
					$table->setCellBGColor($row, $columns{$key} + ('out' eq $direction),'#90ee90'); # light green
					$row++;

					# Get the in and out hr's for ease of use
					my ($in, $out);
	
					for($i=0;$i < @sorted; $i++) {
						last unless $i < $JKFlow::SCOREKEEP;
						$item = $sorted[$i];
	
						if (!(defined($newaggdata{$item}))) { # Add this to aggdata 1x
							$newaggdata{$type}{$item} = { 
								'bytesin'  => $ref->{$type}{$srcdst}{bytes}{$item}{in},
								'bytesout' => $ref->{$type}{$srcdst}{bytes}{$item}{out},
								'pktsin'   => $ref->{$type}{$srcdst}{pkts}{$item}{in},
								'pktsout'  => $ref->{$type}{$srcdst}{pkts}{$item}{out},
								'flowsin'  => $ref->{$type}{$srcdst}{flows}{$item}{in},
								'flowsout' => $ref->{$type}{$srcdst}{flows}{$item}{out}
							};
						}

						#if (!(defined($dnscache{$ip}))) { # No name here?
						#if ($dnscache{$ip} = gethostbyaddr(pack("C4",split(/\./, $ip)),AF_INET)) {
						#	if (1==0) {
						#		$dnscache{$ip} .= "<br>$ip";
						#	} else {
						#		$dnscache{$ip} = $ip;
						#	}
						#}

						$table->addRow( sprintf("#%d",$i+1),
						#$dnscache{$ip},      # IP Name/Address
						$item,						

						# Bits/sec in
						scale("%.1f", ($ref->{$type}{$srcdst}{bytes}{$item}{in}*8)/300),

						# Bits/sec out
						scale("%.1f", ($ref->{$type}{$srcdst}{bytes}{$item}{out}*8)/300),
					
						# Pkts/sec in
						scale("%.1f", ($ref->{$type}{$srcdst}{pkts}{$item}{in}/300)),
				
						# Pkts/sec out
						scale("%.1f", ($ref->{$type}{$srcdst}{pkts}{$item}{out}/300)),
				
						# Flows/sec in
						scale("%.1f", ($ref->{$type}{$srcdst}{flows}{$item}{in}/300)),
				
						# Flows/sec out
						scale("%.1f", ($ref->{$type}{$srcdst}{flows}{$item}{out}/300)) );

						$table->setRowAlign($row, 'RIGHT');
						$table->setCellBGColor($row,
						$columns{$key} + ('out' eq $direction),
						'#add8e6'); # light blue
						$row++;
	  	  			}
	   	 		print HTML "<p>\n$table</p>\n\n";
     	     			}
			}
		}    
		# Print footers
		print HTML "\n</center>\n</body>\n</html>\n";

		# Close the file, and make $scorepage point at this page
		close HTML;

	}

	#unlink $JKFlow::scorepage ||
	#	die "Could not remove $JKFlow::scorepage ($!)\n";
	#   symlink $file, $JKFlow::scorepage ||
	#	die "Could not create symlink to $JKFlow::scorepage ($!)\n";

	if ($JKFlow::aggscorekeep > 0) {
		# Merge newaggdata and aggdata
		foreach $ip (keys %{$newaggdata{hosts}}) {
			$aggdata{$ip}->{'count'}++;
			$aggdata{$ip}->{'bytesin'}  += $newaggdata{hosts}{$ip}->{'bytesin'};
			$aggdata{$ip}->{'bytesout'} += $newaggdata{hosts}{$ip}->{'bytesout'};
			$aggdata{$ip}->{'pktsin'}   += $newaggdata{hosts}{$ip}->{'pktsin'};
			$aggdata{$ip}->{'pktsout'}  += $newaggdata{hosts}{$ip}->{'pktsout'};
			$aggdata{$ip}->{'flowsin'}  += $newaggdata{hosts}{$ip}->{'flowsin'};
			$aggdata{$ip}->{'flowsout'} += $newaggdata{hosts}{$ip}->{'flowsout'};
		}

		# Increment counter
		$aggdata{'numresults'}++;
	
		if ($aggdata{'numresults'} > $JKFlow::NUMKEEP) {
		# Prune this shit
		$aggdata{'numresults'} >>= 1;
		foreach $ip (keys %aggdata) {
			next if ($ip =~ /numresults/);           # Skip this, not a ref
			if ($aggdata{$ip}->{'count'} == 1) {     # Delete singletons
				delete $aggdata{$ip};
			} else {
				$aggdata{$ip}->{'count'}    >>= 1;   # Divide by 2
				$aggdata{$ip}->{'bytesin'}  >>= 1;
				$aggdata{$ip}->{'bytesout'} >>= 1;
				$aggdata{$ip}->{'pktsin'}   >>= 1;
				$aggdata{$ip}->{'pktsout'}  >>= 1;
				$aggdata{$ip}->{'flowsin'}  >>= 1;
				$aggdata{$ip}->{'flowsout'} >>= 1;
			}
		}
	}

	# Write the aggregate table
	&writeAggScoreboard(\%aggdata,$dir);
	
	# Save the aggregation data
	&writeAggFile(\%aggdata,$dir);
    }
	if (defined $ref->{hosts}) {
		delete $ref->{hosts}{src};
		delete $ref->{hosts}{dst};
	}
	if (defined $ref->{ports}) {
		delete $ref->{ports}{src};
		delete $ref->{ports}{dst};
	}
	return;
}

# Simple percentifier, usage percent(1,10) returns 10
# Also stolen from CampusIO.pm
sub percent($$) {
   my $num = shift;
   my $denom = shift;
   return(0) if (0 == $denom);
   return 100*($num/$denom)
}

# Print a large number in sensible units. 
# Arg1 = sprintf format string
# Arg2 = value to put in it.
# Also stolen from CampusIO.pm, where Dave Plonka says...
# This is based somewhat on Tobi Oetiker's code in rrd_graph.c: 
sub scale($$) {
   my $fmt = shift;
   my $value = shift;
   my @symbols = ("a", # 10e-18 Ato
                  "f", # 10e-15 Femto
                  "p", # 10e-12 Pico
                  "n", # 10e-9  Nano
                  "u", # 10e-6  Micro
                  "m", # 10e-3  Milli
                  " ", # Base
                  "k", # 10e3   Kilo
                  "M", # 10e6   Mega
                  "G", # 10e9   Giga
                  "T", # 10e12  Terra
                  "P", # 10e15  Peta
                  "E");# 10e18  Exa

   my $symbcenter = 6;
   my $digits = (0 == $value)? 0 : floor(log($value)/log(1000));
   return sprintf(${fmt} . " %s", $value/pow(1000, $digits),
                  $symbols[$symbcenter+$digits])
}

sub DESTROY {
   my $self = shift;
   $self->SUPER::DESTROY
}

=head1 BUGS

=head1 AUTHOR

Jurgen Kobierczynski <jurgen.kobierczynski@pandora.be>

=head1 REPORT PROBLEMS

Please contact <jurgen.kobierczynski@pandora.be> to get help with JKFlow.

=cut

1
