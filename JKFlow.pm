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
	my $counterke;

my(%ROUTERS);			# A hash mapping exporter IP's to the name
				# we want them to be called, e.g.
				# $ROUTER{"127.0.0.1"} = 'localhost';
my($SUBNETS);			# A trie of the subnets that are 'inside'
my(%SERVICES);			# A hashtable containing services we are
				# interested in. E.g.:
				# $SERVICES{'www'} = { 80 => { 6 } }
				# means that we are interested in www/tcp
				# and that it has label 'www'
my(%myservices);
my(%myalllist);
my($subnet);

my($OUTDIR) = '.';		# The directory we will stow rrd files in

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
	my $config=XMLin('/usr/local/bin/JKFlow.xml',
		forcearray=>['router','subnet','network','direction','application']);

	$JKFlow::OUTDIR = $config->{outputdir};

	if (defined $config->{all}) {
		if (defined $config->{'all'}{'localsubnets'}) {
			$JKFlow::mylist{'all'}{'localsubnets'}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$config->{all}{'localsubnets'})) {
				print "All: + localsubnets subnet $subnet\n";
				$JKFlow::mylist{'all'}{'localsubnets'}->add_string($subnet);
			}
		}
		pushServices(
			$config->{all}{services},
			\%{$JKFlow::mylist{'all'}{'service'}});
		pushProtocols(
			$config->{all}{protocols},
			\%{$JKFlow::mylist{'all'}{'protocol'}});
		if (defined $config->{all}{direction}) { 
			$JKFlow::mylist{'all'}{'direction'}={};
			pushDirections(
				$config->{all}{direction},
				\%{$JKFlow::mylist{'all'}{'direction'}});
		}
		if (defined $config->{all}{application}) { 
			$JKFlow::mylist{'all'}{'application'}={};
			pushApplications( 
				$config->{all}{application},
				\%{$JKFlow::mylist{'all'}{'application'}});
		}
		if (defined $config->{all}{ftp}) {
			$JKFlow::mylist{'all'}{'ftp'}={};
		}
		if (defined $config->{all}{multicast}) {
			$JKFlow::mylist{'all'}{'multicast'}={};
		}
		if (defined $config->{all}{tos}) {
			$JKFlow::mylist{'all'}{'tos'}={};
		}
		if (defined $config->{all}{total}) {
			$JKFlow::mylist{'all'}{'total'}={};
		}
		if (defined $config->{all}{write}) {
			$JKFlow::mylist{'all'}{'write'}=$config->{all}{write};
 		} else {
			$JKFlow::mylist{'all'}{'write'}="yes";
		}

	}

	#use Data::Dumper;
	foreach my $routername (keys %{$config->{routers}{router}}) {
		print "Routers: + router $routername\n";
		if (defined $config->{routers}{router}{$routername}{localsubnets}) {
			$JKFlow::mylist{routers}{router}{$routername}{localsubnets}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$config->{routers}{router}{$routername}{localsubnets})) {
				print "Routers: router $routername + localsubnets subnet $subnet\n";
				$JKFlow::mylist{routers}{router}{$routername}{localsubnets}->add_string($subnet);
			}
		}
		foreach my $router (split(/,/,$config->{routers}{router}{$routername}{routers})) {
			print "Routers: router $routername + routerip $router\n";
			$JKFlow::mylist{'router'}{$routername}{'routers'}{$router}={};
		}
		pushServices(
			$config->{routers}{router}{$routername}{services},
			\%{$JKFlow::mylist{'router'}{$routername}{'service'}});
		pushProtocols(
			$config->{routers}{router}{$routername}{protocols},
			\%{$JKFlow::mylist{'router'}{$routername}{'protocol'}});
		if (defined $config->{routers}{router}{$routername}{direction}) { 
			$JKFlow::mylist{'router'}{$routername}{'direction'}={};
			pushDirections(
				$config->{routers}{router}{$routername}{direction},
				\%{$JKFlow::mylist{'router'}{$routername}{'direction'}});
		}
		if (defined $config->{routers}{router}{$routername}{application}) { 
			$JKFlow::mylist{'router'}{$routername}{'application'}={};
			pushApplications( 
				$config->{routers}{router}{$routername}{application},
				\%{$JKFlow::mylist{'router'}{$routername}{'application'}});
		}
		if (defined $config->{routers}{router}{$routername}{ftp}) {
			$JKFlow::mylist{'router'}{$routername}{'ftp'}={};
		}
		if (defined $config->{routers}{router}{$routername}{multicast}) {
			$JKFlow::mylist{'router'}{$routername}{'multicast'}={};
		}
		if (defined $config->{routers}{router}{$routername}{tos}) {
			$JKFlow::mylist{'router'}{$routername}{'tos'}={};
		}
		if (defined $config->{routers}{router}{$routername}{total}) {
			$JKFlow::mylist{'router'}{$routername}{'total'}={};
		}
		if (defined $config->{routers}{router}{$routername}{write}) {
			$JKFlow::mylist{'router'}{$routername}{'write'}=$config->{routers}{router}{$routername}{write};
 		} else {
			$JKFlow::mylist{'router'}{$routername}{'write'}='yes';
		}
	}

	foreach my $subnetname (keys %{$config->{subnets}{subnet}}) {
		print "Subnets: + subnet $subnetname\n";
		if (defined $config->{subnets}{subnet}{$subnetname}{localsubnets}) {
			$JKFlow::mylist{subnets}{subnet}{$subnetname}{localsubnets}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$config->{subnets}{subnet}{$subnetname}{localsubnets})) {
				print "Subnets: subnet $subnetname + localsubnets subnet $subnet\n";
				$JKFlow::mylist{subnets}{subnet}{$subnetname}{localsubnets}->add_string($subnet);
			}
		}
		${$JKFlow::mylist{'subnet'}{$subnetname}{'subnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
		foreach my $subnet (split(/,/,$config->{subnets}{subnet}{$subnetname}{subnets})) {
			print "Subnets: subnet $subnetname + subnet $subnet\n";
			${$JKFlow::mylist{'subnet'}{$subnetname}{'subnets'}}->add_string($subnet);
			$JKFlow::SUBNETS->add_string($subnet);
		}

		pushServices(
			$config->{subnets}{subnet}{$subnetname}{services},
			\%{$JKFlow::mylist{'subnet'}{$subnetname}{'service'}});
		pushProtocols(
			$config->{subnets}{subnet}{$subnetname}{protocols},
			\%{$JKFlow::mylist{'subnet'}{$subnetname}{'protocol'}});
		if (defined $config->{subnets}{subnet}{$subnetname}{direction}) { 
			$JKFlow::mylist{'subnet'}{$subnetname}{'direction'}={};
			pushDirections(
				$config->{subnets}{subnet}{$subnetname}{direction},
				\%{$JKFlow::mylist{'subnet'}{$subnetname}{'direction'}});
		}
		if (defined $config->{subnets}{subnet}{$subnetname}{application}) { 
			$JKFlow::mylist{'subnet'}{$subnetname}{'application'}={};
			pushApplications( 
				$config->{subnets}{subnet}{$subnetname}{application},
				\%{$JKFlow::mylist{'subnet'}{$subnetname}{'application'}});
		}
		if (defined $config->{subnets}{subnet}{$subnetname}{ftp}) {
			$JKFlow::mylist{'subnet'}{$subnetname}{'ftp'}={};
		}
		if (defined $config->{subnets}{subnet}{$subnetname}{multicast}) {
			$JKFlow::mylist{'subnet'}{$subnetname}{'multicast'}={};
		}
		if (defined $config->{subnets}{subnet}{$subnetname}{tos}) {
			$JKFlow::mylist{'subnet'}{$subnetname}{'tos'}={};
		}
		if (defined $config->{subnets}{subnet}{$subnetname}{total}) {
			$JKFlow::mylist{'subnet'}{$subnetname}{'total'}={};
		}
		if (defined $config->{subnets}{subnet}{$subnetname}{write}) {
			$JKFlow::mylist{'subnet'}{$subnetname}{'write'}=$config->{subnets}{subnet}{$subnetname}{write};
 		} else {
			$JKFlow::mylist{'subnet'}{$subnetname}{'write'}="yes";
		}
	}

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

	pushDirections2( \%{$config->{fromsubnets}}, $JKFlow::fromtrie );
	pushDirections2( \%{$config->{tosubnets}}, $JKFlow::totrie );

	
	if (defined $config->{router}{total_router}) {
		$JKFlow::mylist{'total_router'} = {};
	}
	if (defined $config->{subnet}{total_subnet}) {
		$JKFlow::mylist{'total_subnet'} = {};
	}		
	#use Data::Dumper;
	#print "Data:".Dumper($JKFlow::mylist{subnets})."\n";
	#print "Data:".Dumper($config)."\n";
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
		if (! defined $refxml->{'name'}) {
			$refxml->{'name'}="default";
		}
		
		if (defined $refxml->{$direction}{'fromsubnets'}) {
			${$ref->{$direction}{'fromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'fromsubnets'})) {
				print "Adding fromsubnets subnet $subnet \n";
				${$ref->{$direction}{'fromsubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'tosubnets'}) { 
			${$ref->{$direction}{'tosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'tosubnets'})) {
				print "Adding tosubnets subnet $subnet \n";
				${$ref->{$direction}{'tosubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'nofromsubnets'}) {
			${$ref->{$direction}{'nofromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'nofromsubnets'})) {
				print "Adding nofromsubnets subnet $subnet \n";
				${$ref->{$direction}{'nofromsubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'notosubnets'}) { 
			${$ref->{$direction}{'notosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'notosubnets'})) {
				print "Adding notosubnets subnet $subnet \n";
				${$ref->{$direction}{'notosubnets'}}->add_string($subnet);
			}
		}

		foreach my $fromsubnet (split /,/, $refxml->{$direction}{'fromsubnets'}) {
			foreach my $tosubnet (split /,/, $refxml->{$direction}{'tosubnets'}) {
				print "Subnets: FROM=".$fromsubnet." TO=".$tosubnet."\n";
				my $list=[];
				my $nofromsubnets=[];
				my $notosubnets=[];
				if (defined $JKFlow::mylist{subnets}{$fromsubnet}{$tosubnet}) {
					$list=$JKFlow::mylist{subnets}{$fromsubnet}{$tosubnet};
				}
				foreach my $nofromsubnet (split /,/, $refxml->{$direction}{'nofromsubnets'}) {
					push @{$nofromsubnets},$nofromsubnet;
				}
				foreach my $notosubnet (split /,/, $refxml->{$direction}{'notosubnets'}) {
					push @{$notosubnets},$notosubnet;
				}
				push @{$list},{ 
				nofromsubnets=>$nofromsubnets,
				notosubnets=>$notosubnets,
				ref=>$ref->{$direction}
				};
				$JKFlow::mylist{subnets}{$fromsubnet}{$tosubnet}=$list;
				if ($refxml->{$direction}{'monitor'} eq 'yes') {
					$ref->{$direction}{monitor}="Yes";
				} else {
					$ref->{$direction}{monitor}="No";
				}
			}
		}

		if (defined $refxml->{$direction}{'application'}) { 
			$ref->{$direction}{application}={};
			pushApplications( 
				$refxml->{$direction}{'application'},
				$ref->{$direction}{'application'});
		}
		if (defined $refxml->{$direction}{'services'}) {
			$ref->{$direction}{'service'}={};
			pushServices(
				$refxml->{$direction}{'services'},
				$ref->{$direction}{'service'});
		}
		if (defined $refxml->{$direction}{'protocols'}) {
			$ref->{$direction}{'protocol'}={};
			pushProtocols(
				$refxml->{$direction}{'protocols'},
				$ref->{$direction}{'protocol'});
		}
		if (defined $refxml->{$direction}{'direction'}) {
			$ref->{$direction}{'direction'}={};
			pushDirections(
				$refxml->{$direction}{'direction'},
				$ref->{$direction}{'direction'});
		}
		if (defined $refxml->{$direction}{'ftp'}) {
			$ref->{$direction}{'ftp'}={};
		}
		if (defined $refxml->{$direction}{'multicast'}) {
			$ref->{$direction}{'multicast'}={};
		}
		if (defined $refxml->{$direction}{'tos'}) {
			$ref->{$direction}{'tos'}={};
		}
		if (defined $refxml->{$direction}{'total'}) {
			$ref->{$direction}{'total'}={};
		}
	}
}

sub pushDirections2 {
my $refxml=shift;
my $ref=shift;
my ($srv,$proto,$start,$end,$tmp,$i,$subnet);

		foreach $subnet (@{$refxml->{'subnet'}}) {

			foreach my $addsubnet (split /,/, $subnet->{'subnets'}) {
				my %seen = ();
				my $includedlist = [];
				my $excludedlist = [];
				if (defined $ref->match_string($addsubnet)) {
					push @{$includedlist}, @{${$ref->match_string($addsubnet)}{included}};
					push @{$excludedlist}, @{${$ref->match_string($addsubnet)}{excluded}};
				}
				@{$includedlist} = grep { ! $seen{$_} ++ } ( @{$includedlist}, $addsubnet );
				$ref->add_string($addsubnet,{included=>$includedlist,excluded=>$excludedlist});
			}
			
			foreach my $addsubnet (split /,/, $subnet->{'nosubnets'}) {
				my %seen = ();
				my $includedlist = [];
				my $excludedlist = [];
				if (defined $ref->match_string($addsubnet)) {
					push @{$includedlist}, @{${$ref->match_string($addsubnet)}{included}};
					push @{$excludedlist}, @{${$ref->match_string($addsubnet)}{excluded}};
				}
				@{$excludedlist} = grep { ! $seen{$_} ++ } ( @{$excludedlist}, $addsubnet );
				$ref->add_string($addsubnet,{included=>$includedlist,excluded=>$excludedlist});
			}
			pushDirections2($subnet,$ref);
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

	#$counterke++;
	#print $counterke."\n";
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

	# Counting for specific Routers
	foreach my $routername (keys %{$JKFlow::mylist{'router'}}) {
		$which = 'out';
		if (defined $JKFlow::mylist{'router'}{$routername}{'localsubnets'}) {
			if ($JKFlow::mylist{'router'}{$routername}{'localsubnets'}->match_integer($dstaddr)) {
				$which = 'in';
			} 
		}
		if (defined $JKFlow::mylist{'router'}{$routername}{'routers'}{$exporterip}) {
			countpackets(\%{$JKFlow::mylist{'router'}{$routername}},$which);
			countApplications(\%{$JKFlow::mylist{'router'}{$routername}{'application'}},$which);
			#countDirections(\%{$JKFlow::mylist{'router'}{$routername}{'direction'}},$which);
		}
	}
	# Couting for specific Subnets
	foreach my $subnetname (keys %{$JKFlow::mylist{'subnet'}}) {
		$which = '';
		if (defined $JKFlow::mylist{'subnet'}{$subnetname}{'localsubnets'}) {
			if ($JKFlow::mylist{'subnet'}{$subnetname}{'localsubnets'}->match_integer($dstaddr)) {
				$which = 'in';
			} else {
				$which = 'out';
			}
		}
		if ($which eq 'out' || ${$JKFlow::mylist{'subnet'}{$subnetname}{'subnets'}}->match_integer($srcaddr)) {
			$which = 'out';
			countpackets(\%{$JKFlow::mylist{'subnet'}{$subnetname}},$which);
			countApplications(\%{$JKFlow::mylist{'subnet'}{$subnetname}{'application'}},$which);
			#countDirections(\%{$JKFlow::mylist{'subnet'}{$subnetname}{'direction'}},$which);
		}
		elsif ($which eq 'in' || ${$JKFlow::mylist{'subnet'}{$subnetname}{'subnets'}}->match_integer($dstaddr)) {
			$which = 'in';
			countpackets(\%{$JKFlow::mylist{'subnet'}{$subnetname}},$which);
			countApplications(\%{$JKFlow::mylist{'subnet'}{$subnetname}{'application'}},$which);
			#countDirections(\%{$JKFlow::mylist{'subnet'}{$subnetname}{'direction'}},$which);
		}
	}
	# Counting Directions for specific Networks
	# Note that no general packets/multicasts are counted, because
	# the primary intended function of Networks is to be a compound of several
	# Subnets/Routers
	foreach my $network (keys %{$JKFlow::mylist{'network'}}) {
		#countDirections(\%{$JKFlow::mylist{'network'}{$network}{'direction'}},$which);
	}
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
									print "D2 SRC = ".inet_ntoa(pack(N,$srcaddr)).", SRCSUBNET = $srcsubnet, DST = ".inet_ntoa(pack(N,$dstaddr)).", DSTSUBNET = $dstsubnet \n"; 
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
									print "D2 DST = ".inet_ntoa(pack(N,$dstaddr)).", DSTSUBNET = $dstsubnet, SRC = ".inet_ntoa(pack(N,$srcaddr)).", SRCSUBNET = $srcsubnet \n"; 
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
   my $typeos;

   foreach my $type ('bytes','pkts','flows') {
      foreach my $which ('in','out') {
		if (defined $addref->{'protocol'}) {
			foreach my $protocol (keys %{$addref->{'protocol'}}) { 
				$sumref->{'protocol'}{$protocol}{'total'}{$which}{$type} 
					+= $addref->{'protocol'}{$protocol}{'total'}{$which}{$type};
			}
		}

		if (defined $addref->{'service'}) {
			foreach my $protocol (keys %{$addref->{'service'}}) { 
				foreach my $service (keys %{$addref->{'service'}{$protocol}}) {
					$sumref->{'service'}{$protocol}{$service}{'src'}{$which}{$type} 
						+= $addref->{'service'}{$protocol}{$service}{'src'}{$which}{$type};
					$sumref->{'service'}{$protocol}{$service}{'dst'}{$which}{$type} 
						+= $addref->{'service'}{$protocol}{$service}{'dst'}{$which}{$type};
				}
			}
		}

		if (defined $addref->{'multicast'}) {
         		$sumref->{'multicast'}{'total'}{$which}{$type} 
				+= $addref->{'multicast'}{'total'}{$which}{$type};
		}
		if (defined $addref->{'tos'}) {
			foreach my $typeos ('normal','other') {
			$sumref->{'tos'}{$typeos}{$which}{$type}
				+= $addref->{'tos'}{$typeos}{$which}{$type};
			}
		}
		if (defined $addref->{'total'}) {
			$sumref->{'total'}{$which}{$type} 
				+= $addref->{'total'}{$which}{$type};
		}
      }
   }
}   

sub reporttorrd {

 	use RRDs;			# To actually produce results
	my $self=shift;
	my $file=shift;
	my $ref=shift;
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
				push(@values, $tmp);
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
	my ($file,$tmp);

	# First, always generate a totals report
	# createGeneralRRD we get from our parent, FlowScan
 	# Create a new rrd if one doesn't exist
	if (defined $ref->{'total'}) {	
		$file = $JKFlow::OUTDIR . $dir . "/total.rrd";
		reporttorrd($self,$file,\%{$ref->{'total'}});
	}

	if (defined $ref->{'tos'}) {	
		foreach my $tos ('normal','other') {
			$file = $JKFlow::OUTDIR . $dir . "/tos_". $tos . ".rrd";
			reporttorrd($self,$file,\%{$ref->{'tos'}{$tos}});
 		}
	}

	if (defined $ref->{'multicast'}) {	
		$file = $JKFlow::OUTDIR . $dir . "/protocol_multicast.rrd";
		reporttorrd($self,$file,\%{$ref->{'multicast'}{'total'}});
	}

	if (defined $ref->{'protocol'}) {	
		foreach my $protocol (keys %{$ref->{'protocol'}}) {
			if (!($tmp = getprotobynumber($protocol))) {
				$tmp = $protocol;
			}
			$file = $JKFlow::OUTDIR. $dir . "/protocol_" . $tmp . ".rrd";
			reporttorrd($self,$file,\%{$ref->{'protocol'}{$protocol}{'total'}});
		}
	}

	if (defined $ref->{'service'}) {	
		foreach my $src ('src','dst') {
			foreach my $protocol (keys %{$ref->{'service'}}) {
				foreach my $srv (keys %{$ref->{'service'}{$protocol}}) {
					if (!($tmp = getservbyport ($srv, getprotobynumber($protocol)))) {
						$tmp = $srv;
					}
					$file = $JKFlow::OUTDIR. $dir . "/service_" . getprotobynumber($protocol). "_". $tmp . "_" . $src . ".rrd";
					reporttorrd($self,$file,\%{$ref->{'service'}{$protocol}{$srv}{$src}});
				}
			}
		}
	}

	if (defined $ref->{'application'}) {	
		foreach my $src ('src','dst') { 
			foreach my $application (keys %{$ref->{'application'}}) {
  	     			$file = $JKFlow::OUTDIR. $dir . "/service_" . $application . "_" . $src . ".rrd";
				reporttorrd($self,$file,\%{$ref->{'application'}{$application}{$src}});
			}
		}
	}

	if (defined $ref->{'ftp'}) {	
		foreach my $src ('src','dst') { 
  	     		$file = $JKFlow::OUTDIR. $dir . "/service_ftp_" . $src . ".rrd";
			reporttorrd($self,$file,\%{$ref->{'ftp'}{$src}});
		}
		foreach my $pair (keys %{$ref->{'ftp'}{cache}}) {
			if ($self->{filetime}-$ref->{'ftp'}{cache}{$pair} > 2*60*60 ||
			    $self->{filetime}-$ref->{'ftp'}{cache}{$pair} < -15 * 60 ) {
				#print "Deleted FTP-session: $pair Timediff:".($self->{filetime}-$ref->{'ftp'}{cache}{$pair})."\n";	
				delete($ref->{'ftp'}{cache}{$pair});
			}
		}
	}

	if (defined $ref->{'direction'}) {
		foreach my $direction (keys %{$ref->{'direction'}}) {
			if (! -d $JKFlow::OUTDIR . $dir."/".$direction ) {
				mkdir($JKFlow::OUTDIR . $dir . "/" . $direction ,0755);
			}
			reporttorrdfiles($self, $dir . "/" . $direction, \%{$ref->{'direction'}{$direction}});
		}
	}
}

sub report {
	my $self = shift;
	my($file) = $JKFlow::OUTDIR . "/total.rrd";
	my($routerfile);
	my(@values) = ();
	my(@array);
	my($count, $i ,$j ,$k , $tmp,$srv,$rt,$sn, $subnetdir,$routerdir);

	if (defined $JKFlow::mylist{'total_router'}) {
		foreach my $router (keys %{$JKFlow::mylist{'router'}}) {
			summarize(\%{$JKFlow::mylist{'total_router'}},\%{$JKFlow::mylist{'router'}{$router}});
		}
	}
	if (defined $JKFlow::mylist{'total_subnet'}) {
		foreach my $subnet (keys %{$JKFlow::mylist{'subnet'}}) {
			summarize(\%{$JKFlow::mylist{'total_subnet'}},\%{$JKFlow::mylist{'subnet'}{$subnet}});
		}
	}

	foreach my $network (keys %{$JKFlow::mylist{'network'}}) {
 		foreach my $router (keys %{$JKFlow::mylist{'network'}{$network}{'router'}}) {
			print "Summarize $network, $router \n";
			summarize(\%{$JKFlow::mylist{'network'}{$network}},\%{$JKFlow::mylist{'router'}{$router}});
		}
		foreach my $subnet (keys %{$JKFlow::mylist{'network'}{$network}{'subnet'}}) {
			print "Summarize $network, $subnet \n";
			summarize(\%{$JKFlow::mylist{'network'}{$network}},\%{$JKFlow::mylist{'subnet'}{$subnet}});
		}
	}  
	
	if (${$JKFlow::mylist{'all'}}{'write'} eq 'yes') {
		if (! -d $JKFlow::OUTDIR."/all" ) {
			mkdir($JKFlow::OUTDIR."/all",0755);
		}
		reporttorrdfiles($self,"/all",\%{$JKFlow::mylist{'all'}});
	}

	if (! -d $JKFlow::OUTDIR."/total_router" ) {
		mkdir($JKFlow::OUTDIR."/total_router",0755);
	}
	reporttorrdfiles($self,"/total_router",\%{$JKFlow::mylist{'total_router'}});
    
	if (! -d $JKFlow::OUTDIR."/total_subnet" ) {
		mkdir($JKFlow::OUTDIR."/total_subnet",0755);
	}
	reporttorrdfiles($self,"/total_subnet",\%{$JKFlow::mylist{'total_subnet'}});

	foreach my $router (keys %{$JKFlow::mylist{'router'}}) {
		if (${$JKFlow::mylist{'router'}{$router}}{'write'} eq 'yes') {
			print "Router:$router\n";
			if (! -d $JKFlow::OUTDIR . "/router_$router" ) {
				mkdir($JKFlow::OUTDIR . "/router_$router",0755);
			}
			reporttorrdfiles($self,"/router_".$router,\%{$JKFlow::mylist{'router'}{$router}});
		}
	}

	foreach my $subnet (keys %{$JKFlow::mylist{'subnet'}}) {
		if (${$JKFlow::mylist{'subnet'}{$subnet}}{'write'} eq 'yes') {
			($subnetdir=$subnet) =~ s/\//_/g;
			if (! -d $JKFlow::OUTDIR ."/subnet_$subnetdir" ) {
				mkdir($JKFlow::OUTDIR ."/subnet_$subnetdir",0755);
			}
			reporttorrdfiles($self,"/subnet_".$subnetdir,\%{$JKFlow::mylist{'subnet'}{$subnet}});
		}
	}
    
	foreach my $network (keys %{$JKFlow::mylist{'network'}}) {
		if (! -d $JKFlow::OUTDIR."/network_".$network ) {
			mkdir($JKFlow::OUTDIR."/network_".$network,0755);
		}
		reporttorrdfiles($self,"/network_".$network,\%{$JKFlow::mylist{'network'}{$network}});
	}
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

sub DESTROY {
   my $self = shift;
   $self->SUPER::DESTROY
}

=head1 BUGS


=head1 AUTHOR

Jurgen Kobierczynski <jkobierczynski@hotmail.com>

=head1 REPORT PROBLEMS

Please contact <cuflow-users@columbia.edu> to get help with JKFlow.

=cut

1
