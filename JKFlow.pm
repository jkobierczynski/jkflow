#!/usr/local/bin/perl 
# JKFlow.pm - A (hopefully) slightly faster implementation of some of the 
# functionality of SubnetIO.pm, in a slightly more configurable fashion
# Owes *VERY* heavily to Dave Plonka's SubnetIO.pm and CampusIO.pm
# Thanks, Dave :) <plonka@doit.wisc.edu>

# To Add:
# ICMP type handling as a Service, ie 6/icmp Echo
# Make Networks record services? How, while still being fast?

use strict;
use Data::Dumper;

package JKFlow;

require 5;
require Exporter;

@JKFlow::ISA=qw(FlowScan Exporter);

# convert the RCS revision to a reasonable Exporter VERSION:
'$Revision$ ' =~ m/(\d+)\.(\d+)/ && (( $JKFlow::VERSION ) = sprintf("%d.%03d", $1, $2));

=head1 NAME

JKFlow - flowscan module that is a little more configurable than
SubnetIO.pm in return for sacrificing some modularity.

=head1 SYNOPSIS

   $ flowscan JKFlow

or in F<flowscan.cf>:

   ReportClasses JKFlow

=head1 DESCRIPTION

JKFlow.pm creates rrds matching the configuration given in JKFlow.cf. It 
(by default) creates a 'total.rrd' file, representing the total in and 
out-bound traffic it receives. It also creates 2 rrd files for every 
B<Service> directive in JKFlow.cf, service_servicename_src.rrd and 
service_servicename_dst.rrd.

=head1 CONFIGURATION

JKFlow's configuration file is F<JKFlow.cf>. This configuration file is
located in the directory in which the F<flowscan> script resides.

In this file, blank lines, and any data after a pound sign (#) are ignored.
Directives that can be put in this file include:

=over 4

=item B<Router>

By default, JKFlow does not care from which router the flow records it is
processing are from. Unless you specify a Router statement, it just
aggregates all the traffic it gets and produces rrd files based on the
total. But, if you put

	# Separate out traffic from foorouter
	# Router <Ip Address> <optional alias>
	Router 127.0.0.5 foorouter

In addition to generating the totals rrd files it normally does in
OutputDir, it will create a directory whose name is the IP address specified
(or the alias, if one is provided), and create all the same service_*,
protocol_*, and total.rrd files in it, except only for traffic passed from
the router whose address is <Ip Address>.

Note that it does not make any sense to have Router statements in your
config unless you have more than one router feeding flow records to flowscan
(with one router, the results in the per-router directory will be identical
to the total records in OutputDir)

=item B<Subnet>

Each B<Subnet> entry in the file is an IP/length pair that represents a local
subnet. E.g.:

	# Subnet for main campus
	Subnet 128.59.0.0/16

Add as many of these as is necessary. JKFlow does not generate additional
reports per subnet, as does CampusIO, it simply treats any packet destined
to an address *not* in any of its Subnet statements as an outbound packet.
The Subnet statements are solely to determine if a given IP address is "in" 
your network or not. For subnet-specific reporting, see the Network item
below.

=item B<Network>

Each B<Network> statement in the cf file is used to generate an rrd file
describing the bytes, packets, and flows in and out of a group of IP 
addresses. E.g.:

	# Watson Hall traffic
	Network 128.59.39.0/24,128.59.31.0/24 watson

It consists of a comma separated list of 1 or more CIDR blocks, followed by
a label to apply to traffic into/out of those blocks. It creates rrd files
named 'network_label.rrd'. Note that these are total traffic seen only,
unfortunately, and not per-exporter as Service and Protocol are.

=item B<Service>

Each B<Service> entry in the file is a port/protocol name that we are
interested in, followed by a label. E.g.:

	# Usenet news
	Service nntp/tcp news

In this case, we are interested in traffic to or from port 119 on TCP, and
wish to refer to such traffic as 'news'. The rrd files that will be created
to track this traffic will be named 'service_news_src.rrd' (tracking traffic
whose source port is 119) and 'service_news_dst.rrd' (for traffic with dst
port 119).  Each B<Service> entry will produce these 2 service files. 

The port and protocol can either be symbolic (nntp, tcp), or absolute
numeric (119, 6). If a name is symbolic, we either getservbyname or
getprotobyname as appropriate.

B<Service> tags may also define a range or group of services that should 
be aggregated together. E.g:

	# RealServer traffic
	Service 7070/tcp,554/tcp,6970-7170/udp realmedia

This means that we will produce a 'service_realmedia_dst.rrd' and 
'service_realmedia_src.rrd' files, which will contain traffic data for
the sum of the port/protocol pairs given above.

=item B<Multicast>

Add B<Multicast> to your JKFlow.cf file to enable our cheap multicast hack.
E.g. :
	# Log multicast traffic
	Multicast

Unfortunately, in cflow records, multicast traffic always has a nexthop
address of 0.0.0.0 and an output interface of 0, meaning by default JKFlow
drops it (but counts for purposes of total.rrd). If you enable this option,
JKFlow will create protocol_multicast.rrd in OutputDir (and
exporter-specific rrd's for any Router statements you have)

=item B<Protocol>

Each B<Protocol> entry means you are interested in gathering summary
statistics for the protocol named in the entry. E.g.:

	# TCP
	Protocol 6 tcp

Each protocol entry creates an rrd file named protocol_<protocol>.rrd in
B<OutputDir> The protocol may be specified either numerically (6), or
symbolically (tcp). It may be followed by an optional alias name. If
symbolic, it will be resolved via getprotobyname. The rrd file will be named
according to the alias, or if one is not present, the name/number supplied.

=item B<TOS>

Each B<TOS> entry means you are interested in gathering summary statistics
for traffic whose TOS flag is contained in the range of the entry. E.g.:

	# Normal
	TOS 0 normal

Each TOS entry creates an rrd file named tos_<tos>.rrd in B<OutputDir>. The
TOS value must be specified numerically. The rrd file will be named
according to the alias.

Similar to Service tags, you may define ranges or groups of TOS values to
record together. E.g.:

	# first 8 values
	TOS 0-7 normal  

This will graph data about all flows with the matching TOS data. TOS values
are between 0 and 255 inclusive.

=item B<OutputDir>

This is the directory where the output rrd files will be written.
E.g.:

	# Output to rrds
	OutputDir rrds

=item B<Scoreboard>

The Scoreboard directive is used to keep a running total of the top
consumers of resources. It produces an html reports showing the top N (where
N is specified in the directive) source addresses that sent the most (bytes,
packets, flows) out, and the top N destination addresses that received the
most (bytes, packets, flows) from the outside. Its syntax is

	# Scoreboard <NumberResults> <RootDir> <CurrentLink>
	Scoreboard 10 /html/reports /html/current.html

The above indicates that each table should show the top 10 of its category,
to keep past reports in the /html/reports directory, and the latest report
should be pointed to by current.html.

Within RootDir, we create a directory per day, and within that, a directory
per hour of the day. In each of these directories, we write the scoreboard
reports. 

Scoreboarding measures all traffic we get flows for, it is unaffected by any
Router statements in your config.

=item B<AggregateScore>

The AggregateScore directive indicates that JKFlow should keep running totals
for the various Scoreboard categories, and generate an overall report based 
on them, updating it every time it creates a new Scoreboard file. E.g.:

	# AggregateScore <NumberToPrint> <Data File> <OutFile>
	AggregateScore 10 /html/reports/totals.dat /html/topten.html

If you configure this option, you must also turn on
Scoreboard. /html/reports/totals.dat is a data file containing an easily
machine-readable form of the last several ScoreBoard reports. It then takes
each entries average values for every time it has appeared in a
ScoreBoard. Then it prints the top NumberToPrint of those. Every 100
samples, it drops all entries that have only appeared once, and divides all
the others by 2 (including the number of times they have appeared). So, if a
given host were always in the regular ScoreBoard, its appearance count
would slowly grow from 50 to 100, then get cut in half, and repeat.

This is usefull for trend analysis, as it enables you to see which hosts are
*always* using bandwidth, as opposed to outliers and occasional users.

AggregateScoreboarding measures all traffic we get flows for, it is
unaffected by any Router statements in your config.

=back

=cut

use Cflow qw(:flowvars 1.015);  # for use in wanted sub
use RRDs;			# To actually produce results
use Socket;			# We need inet_aton
use Net::Patricia;		# Fast IP/mask lookups
use POSIX;			# We need floor()
use FindBin;			# To find our executable
use XML::Simple;

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
my($which);
my($subnet);

my($OUTDIR) = '.';		# The directory we will stow rrd files in

#my($scorekeep) = 0;	        # The top N addresses to report on. By default
				# don't keep scoreboards.
#my($scoredir)  = undef;		# The directory to put the tree of reports in
#my($scorepage) = undef;		# The link to the current page

#my($aggscorekeep) = 0;		# Do not create an overall rankings file

#$JKFlow::NUMKEEP = 50;		# How many aggregates to keep

$JKFlow::multicast = 0;		# Do multicast? Default no.

# Multicast address spec's, taken from CampusIO
$JKFlow::MCAST_NET  = unpack('N', inet_aton('224.0.0.0'));
$JKFlow::MCAST_MASK = unpack('N', inet_aton('240.0.0.0'));

$JKFlow::SUBNETS = new Net::Patricia || die "Could not create a trie ($!)\n";
&parseConfig;	# Read our config file

sub parseConfig {
    my($ip,$mask,$srv,$proto,$label,$tmp,$txt);
    my($num,$dir,$current,$start,$end,$i,$subnet,$router,$networkname);

	use XML::Simple;
	my $config=XMLin('/usr/local/bin/JKFlow.xml');

	$JKFlow::OUTDIR = $config->{outputdir};

	if (defined $config->{all}) {

		pushServices(
			$config->{all}{services},
			\%{$JKFlow::mylist{'all'}{'service'}});
		pushProtocols(
			$config->{all}{protocols},
			\%{$JKFlow::mylist{'all'}{'protocol'}});
		pushDirections(
			$config->{all}{direction},
			\%{$JKFlow::mylist{'all'}{'direction'}});

		if (defined $config->{all}{multicast}) {
			$JKFlow::mylist{'all'}{'multicast'}={};
		}
		if (defined $config->{all}{tos}) {
			$JKFlow::mylist{'all'}{'tos'}={};
		}
		if (defined $config->{all}{total}) {
			$JKFlow::mylist{'all'}{'total'}={};
		}

	}

	#use Data::Dumper;
	foreach my $router (keys %{$config->{routers}{router}}) {
		my $routerip = $config->{routers}{router}{$router}{ipaddress};
		$JKFlow::mylist{'router'}{$routerip}{'name'} = $router;

		pushServices(
			$config->{routers}{router}{$router}{services},
			\%{$JKFlow::mylist{'router'}{$routerip}{'service'}});
		pushProtocols(
			$config->{routers}{router}{$router}{protocols},
			\%{$JKFlow::mylist{'router'}{$routerip}{'protocol'}});
		pushDirections(
			$config->{routers}{router}{$router}{direction},
			\%{$JKFlow::mylist{'router'}{$routerip}{'direction'}});

		if (defined $config->{routers}{router}{$router}{multicast}) {
			$JKFlow::mylist{'router'}{$routerip}{'multicast'}={};
		}
		if (defined $config->{routers}{router}{$router}{tos}) {
			$JKFlow::mylist{'router'}{$routerip}{'tos'}={};
		}
		if (defined $config->{routers}{router}{$router}{total}) {
			$JKFlow::mylist{'router'}{$routerip}{'total'}={};
		}

	}

	foreach my $subnet (keys %{$config->{subnets}{subnet}}) {
		$JKFlow::SUBNETS->add_string($subnet);

		pushServices(
			$config->{subnets}{subnet}{$subnet}{services},
			\%{$JKFlow::mylist{'subnet'}{$subnet}{'service'}});
		pushProtocols(
			$config->{subnets}{subnet}{$subnet}{protocols},
			\%{$JKFlow::mylist{'subnet'}{$subnet}{'protocol'}});
		pushDirections(
			$config->{subnets}{subnet}{$subnet}{direction},
			\%{$JKFlow::mylist{'subnet'}{$subnet}{'direction'}});

		if (defined $config->{subnets}{subnet}{$subnet}{multicast}) {
			$JKFlow::mylist{'subnet'}{$subnet}{'multicast'}={};
		}
		if (defined $config->{subnets}{subnet}{$subnet}{tos}) {
			$JKFlow::mylist{'subnet'}{$subnet}{'tos'}={};
		}
		if (defined $config->{subnets}{subnet}{$subnet}{total}) {
			$JKFlow::mylist{'subnet'}{$subnet}{'total'}={};
		}

	}

	foreach my $network (keys %{$config->{networks}{network}}) {

		pushDirections(
			$config->{networks}{network}{$network}{direction},
			\%{$JKFlow::mylist{'network'}{$network}{'direction'}});

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
	
	if (defined $config->{router}{total_router}) {
		$JKFlow::mylist{'total_router'} = {};
	}
	if (defined $config->{subnet}{total_subnet}) {
		$JKFlow::mylist{'total_subnet'} = {};
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

sub pushDirections {
my $refxml=shift;
my $ref=shift;
my ($srv,$proto,$start,$end,$tmp,$i);

	#use Data::Dumper;
	#print "refxml=".Dumper($refxml)."\n";
	#print "ref=".Dumper($ref)."\n";
	if (! defined $refxml->{'name'}) {
		$refxml->{'name'}="default";
	}
	if (defined $refxml->{'fromsubnet'}) {
		$ref->{$refxml->{'name'}}{'fromsubnet'}=new Net::Patricia || die "Could not create a trie ($!)\n";
		$ref->{$refxml->{'name'}}{'fromsubnet'}->add_string($refxml->{'fromsubnet'});
	}
	if (defined $refxml->{'tosubnet'}) { 
		$ref->{$refxml->{'name'}}{'tosubnet'}=new Net::Patricia || die "Could not create a trie ($!)\n";
		$ref->{$refxml->{'name'}}{'tosubnet'}->add_string($refxml->{'tosubnet'});
	}
	foreach my $application (keys %{$refxml->{'application'}}) {
		foreach my $current (split(/,/,$refxml->{'application'}{$application}{'content'})) {
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
						$ref->{$refxml->{'name'}}{'application'}{$application}{'service'}{$proto}{$i} = {};
					}
				} else {
					if ($srv !~ /\d+/) {
						$tmp = getservbyname($srv, getprotobynumber($proto)) || die "Unknown service $srv on line $.\n";
						$srv = $tmp;
					}
					$ref->{$refxml->{'name'}}{'application'}{$application}{'service'}{$proto}{$srv} = {};
				}
			} else {
				die "Bad Service Item $current on line $.\n";
			}
		}	
	}
	if (defined $refxml->{'services'}) {
		$ref->{$refxml->{'name'}}{'service'}={};
		pushServices(
			$refxml->{'services'},
			$ref->{$refxml->{'name'}}{'service'});
	}
	if (defined $refxml->{'protocols'}) {
		$ref->{$refxml->{'name'}}{protocol}={};
		pushProtocols(
			$refxml->{'protocols'},
			$ref->{$refxml->{'name'}}{'protocol'});
	}
	if (defined $refxml->{'multicast'}) {
		$ref->{$refxml->{'name'}}{'multicast'}={};
	}
	if (defined $refxml->{'tos'}) {
		$ref->{$refxml->{'name'}}{'tos'}={};
	}
	if (defined $refxml->{'total'}) {
		$ref->{$refxml->{'name'}}{'total'}={};
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

    	# ######### Are the flows Inbound or outbound? #########
	# The decision is based on the destination address of the flow
	# is included in one of the subnets defined in the subnets element
	# in the JKFlow.xml file. If no subnets were defined, then all
	# flows are outbound!

	if ($JKFlow::SUBNETS->match_integer($dstaddr)) {
		$which = 'in';
	} else {
		$which = 'out';
	}


	# Counting ALL
	if (defined $JKFlow::mylist{'all'}) {

		countpackets(\%{$JKFlow::mylist{'all'}},$which);
		countDirections(\%{$JKFlow::mylist{'all'}{'direction'}});
    		if (($dstaddr & $JKFlow::MCAST_MASK) == $JKFlow::MCAST_NET) {
        		countmulticasts(\%{$JKFlow::mylist{'all'}});
		}

	}

	# Counting for specific Routers
	if (defined $JKFlow::mylist{'router'}{$exporterip}) {

		countpackets(\%{$JKFlow::mylist{'router'}{$exporterip}});
		countDirections(\%{$JKFlow::mylist{'router'}{$exporterip}{'direction'}});
		#only $dstaddr can be a multicast address 
    		if (($dstaddr & $JKFlow::MCAST_MASK) == $JKFlow::MCAST_NET) {
        		countmulticasts(\%{$JKFlow::mylist{'router'}{$exporterip}});
		}

	}

	# Couting for specific Subnets
   	if (($subnet = $JKFlow::SUBNETS->match_integer($dstaddr)) 
	|| ($subnet = $JKFlow::SUBNETS->match_integer($srcaddr))) {

		countpackets(\%{$JKFlow::mylist{'subnet'}{$subnet}},$which);
		countDirections(\%{$JKFlow::mylist{'subnet'}{$subnet}{'direction'}});
		if ($subnet = $JKFlow::SUBNETS->match_integer($srcaddr)) {
	    		$which = 'out';
        		countmulticasts(\%{$JKFlow::mylist{'subnet'}{$subnet}});
		} else {
			# Do we get directed broadcasts?
	    		$which = 'in';
			countmulticasts(\%{$JKFlow::mylist{'subnet'}{$subnet}});
		}
	}
	# Counting Directions for specific Networks
	# Note that no general packets/multicasts are counted, because
	# the primary intended function of Networks is to be a compound of several
	# Subnets/Routers
	foreach my $network (keys %{$JKFlow::mylist{'network'}}) {
		countDirections(\%{$JKFlow::mylist{'network'}{$network}{'direction'}});
	}

    return 1;
}

sub countDirections {
my $ref=shift;

	foreach my $direction (keys %{$ref}) {
		if ((!defined $ref->{$direction}{'tosubnet'}) && (!defined $ref->{$direction}{'fromsubnet'})) {
			#print "notosubnet, nofromsubnet\n";
    			#use Data::Dumper;
    			#print Dumper(%{$ref->{$direction}})."\n";
	 		countpackets (\%{$ref->{$direction}},$which);
			foreach my $application (keys %{$ref->{$direction}{'application'}}) {
				if (		(defined $ref->{$direction}{'application'}{$application}{'service'}) 
					&& 	(defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol})) {
					if (defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol}{$srcport}) {
						$ref->{$direction}{'application'}{$application}{'src'}{$which}{'flows'}++;
						$ref->{$direction}{'application'}{$application}{'src'}{$which}{'bytes'} += $bytes;
						$ref->{$direction}{'application'}{$application}{'src'}{$which}{'pkts'} += $pkts;
					}
					if (defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol}{$dstport}) {
						$ref->{$direction}{'application'}{$application}{'dst'}{$which}{'flows'}++;
						$ref->{$direction}{'application'}{$application}{'dst'}{$which}{'bytes'} += $bytes;
						$ref->{$direction}{'application'}{$application}{'dst'}{$which}{'pkts'} += $pkts;
					}
				}
			}
		}
		elsif ( (!defined $ref->{$direction}{'tosubnet'} || ($ref->{$direction}{'tosubnet'}->match_integer($dstaddr)))
			 &&  (!defined $ref->{$direction}{'fromsubnet'} || ($ref->{$direction}{'fromsubnet'}->match_integer($srcaddr))) ) {
				#print "tosubnet".$ref->{$direction}{'tosubnet'}->match_integer($dstaddr).",";
				#print "fromsubnet".$ref->{$direction}{'fromsubnet'}->match_integer($srcaddr)."\n";
    				#use Data::Dumper;
    				#print Dumper(%{$ref->{$direction}})."\n";
	 			countpackets (\%{$ref->{$direction}},'out');
				foreach my $application (keys %{$ref->{$direction}{'application'}}) {
					if (		(defined $ref->{$direction}{'application'}{$application}{'service'}) 
						&& 	(defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol})) {
						if (defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol}{$srcport}) {
							$ref->{$direction}{'application'}{$application}{'src'}{'out'}{'flows'}++;
							$ref->{$direction}{'application'}{$application}{'src'}{'out'}{'bytes'} += $bytes;
							$ref->{$direction}{'application'}{$application}{'src'}{'out'}{'pkts'} += $pkts;
						}
						if (defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol}{$dstport}) {
							$ref->{$direction}{'application'}{$application}{'dst'}{'out'}{'flows'}++;
							$ref->{$direction}{'application'}{$application}{'dst'}{'out'}{'bytes'} += $bytes;
							$ref->{$direction}{'application'}{$application}{'dst'}{'out'}{'pkts'} += $pkts;
						}
					}
				}
		}
		elsif ( (!defined $ref->{$direction}{'fromsubnet'} || ($ref->{$direction}{'fromsubnet'}->match_integer($dstaddr)))
			 &&  (!defined $ref->{$direction}{'tosubnet'} || ($ref->{$direction}{'tosubnet'}->match_integer($srcaddr))) ) {
				#print "fromsubnet".$ref->{$direction}{'fromsubnet'}->match_integer($dstaddr).",";
				#print "tosubnet".$ref->{$direction}{'tosubnet'}->match_integer($srcaddr)."\n";
    				#use Data::Dumper;
    				#print Dumper(%{$ref->{$direction}})."\n";
	 			countpackets (\%{$ref->{$direction}},'in');
				foreach my $application (keys %{$ref->{$direction}{'application'}}) {
					if (		(defined $ref->{$direction}{'application'}{$application}{'service'}) 
						&& 	(defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol})) {
						if (defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol}{$srcport}) {
							$ref->{$direction}{'application'}{$application}{'src'}{'in'}{'flows'}++;
							$ref->{$direction}{'application'}{$application}{'src'}{'in'}{'bytes'} += $bytes;
							$ref->{$direction}{'application'}{$application}{'src'}{'in'}{'pkts'} += $pkts;
						}
						if (defined $ref->{$direction}{'application'}{$application}{'service'}{$protocol}{$dstport}) {
							$ref->{$direction}{'application'}{$application}{'dst'}{'in'}{'flows'}++;
							$ref->{$direction}{'application'}{$application}{'dst'}{'in'}{'bytes'} += $bytes;
							$ref->{$direction}{'application'}{$application}{'dst'}{'in'}{'pkts'} += $pkts;
						}
					}
				}
		}
		countpackets(\%{$ref->{$direction}},$which);
	    	if (($dstaddr & $JKFlow::MCAST_MASK) == $JKFlow::MCAST_NET) {
        		countmulticasts(\%{$ref->{$direction}});
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
	if ((defined $ref->{'protocol'}) && (defined $ref->{'protocol'}{$protocol})) {
      		$ref->{'protocol'}{$protocol}{'total'}{$which}{'flows'}++;
		$ref->{'protocol'}{$protocol}{'total'}{$which}{'bytes'} += $bytes;
		$ref->{'protocol'}{$protocol}{'total'}{$which}{'pkts'} += $pkts;
		$ref->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{'flows'}++;
		$ref->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{'bytes'} += $bytes;
		$ref->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{'pkts'} += $pkts;
	}
	if ((defined $ref->{'service'}) && (defined $ref->{'service'}{$protocol})) {
		if (defined $ref->{'service'}{$protocol}{$srcport}) {
			$ref->{'service'}{$protocol}{$srcport}{'src'}{$which}{'flows'}++;
			$ref->{'service'}{$protocol}{$srcport}{'src'}{$which}{'bytes'} += $bytes;
			$ref->{'service'}{$protocol}{$srcport}{'src'}{$which}{'pkts'} += $pkts;
		}
		if (defined $ref->{'service'}{$protocol}{$dstport}) {
			$ref->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'flows'}++;
			$ref->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'bytes'} += $bytes;
			$ref->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'pkts'} += $pkts;
		}
	}
}

sub countmulticasts {
    my $ref = shift;
    my $typeos;
	if (defined $ref->{'multicast'}) {
		$ref->{'multicast'}{'total'}{$which}{'flows'}++;
		$ref->{'multicast'}{'total'}{$which}{'bytes'} += $bytes;
		$ref->{'multicast'}{'total'}{$which}{'pkts'} += $pkts;
		if ($tos == 0) {
			$typeos="normal";
		} else {
			$typeos="other"; 
		}
		$ref->{'multicast'}{'tos'}{$typeos}{$which}{'flows'}++;
		$ref->{'multicast'}{'tos'}{$typeos}{$which}{'bytes'} += $bytes;
		$ref->{'multicast'}{'tos'}{$typeos}{$which}{'pkts'} += $pkts;
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
				foreach my $typeos ('normal','other') {
					$sumref->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{$type}
						+= $addref->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{$type};
				}
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
			foreach my $typeos ('normal','other') {
				$sumref->{'multicast'}{'tos'}{$typeos}{$which}{$type} 
					+= $addref->{'multicast'}{'tos'}{$typeos}{$which}{$type};
			}
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

sub reporttorrdfiles {

   
    use RRDs;			# To actually produce results
    my $self=shift;
    my $dir=shift;
    my $reference=shift;
    my ($file,$tmp);
    my @values = ();

    # First, always generate a totals report
    # createGeneralRRD we get from our parent, FlowScan
    # Create a new rrd if one doesn't exist
    $file = $JKFlow::OUTDIR . $dir . "/total.rrd";
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
             if (!(defined($tmp = $reference->{'total'}{$j}{$i}))) {
                  push(@values, 1);
             }
             else {
                  push(@values, $tmp);
                  $reference->{'total'}{$j}{$i}=0;
             }
	}
    }
    $self->updateRRD($file, @values);
    print "File: $file @values\n";
    foreach my $tos ('normal','other') {
    	@values = ();
    	$file = $JKFlow::OUTDIR . $dir . "/tos_". $tos . ".rrd";
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
        	     if (!(defined($tmp = $reference->{'tos'}{$tos}{$j}{$i}))) {
                	  push(@values, 0);
	             }
        	     else {
                	  push(@values, $tmp);
                          $reference->{'tos'}{$tos}{$j}{$i}=0;
             	     }
                }
            }
    	$self->updateRRD($file, @values);
    	print "File: $file @values\n";
    }
    
    @values = ();
    $file = $JKFlow::OUTDIR . $dir . "/protocol_multicast.rrd";
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
             if (!(defined($tmp = $reference->{'multicast'}{'total'}{$j}{$i}))) {
                  push(@values, 0);
             }
             else {
                  push(@values, $tmp);
                  $reference->{'multicast'}{'total'}{$j}{$i}=0;
             }
        }
    }
    $self->updateRRD($file, @values);
    print "File: $file @values\n";
 
    foreach my $protocol (keys %{$reference->{'protocol'}}) {
          if (!($tmp = getprotobynumber($protocol))) {
	    $tmp = $protocol;
          }
          $file = $JKFlow::OUTDIR. $dir . "/protocol_" . $tmp . ".rrd";
          @values = ();
	  foreach my $i ('bytes','pkts','flows') {
	        foreach my $j ('in','out') {
                      if (!(defined($tmp = $reference->{'protocol'}{$protocol}{'total'}{$j}{$i}))) {
                         push(@values, 0);
                      }
                      else {        
		         push(@values, $tmp);
                         $reference->{'protocol'}{$protocol}{'total'}{$j}{$i}=0;
                      }
                   }
          }
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
	  $self->updateRRD($file, @values);
	  print "File: $file @values\n";
    }
   
    foreach my $src ('src','dst') { 
      foreach my $protocol (keys %{$reference->{'service'}}) {
      	     foreach my $srv (keys %{$reference->{'service'}{$protocol}}) {
                if (!($tmp = getservbyport ($srv, getprotobynumber($protocol)))) {
		  $tmp = $srv;
                }
	        $file = $JKFlow::OUTDIR. $dir . "/service_" . getprotobynumber($protocol). "_". $tmp . "_" . $src . ".rrd";
	        @values = ();
	        foreach my $i ('bytes','pkts','flows') {
	           foreach my $j ('in','out') {
                      if (!(defined($tmp = $reference->{'service'}{$protocol}{$srv}{$src}{$j}{$i}))) {
                         push(@values, 0);
                      }
                      else {        
		         push(@values, $tmp);
                         $reference->{'service'}{$protocol}{$srv}{$src}{$j}{$i}=0;
                      }
                   }
                }
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
	        $self->updateRRD($file, @values);
		print "File: $file @values\n";
             }
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
    use Data::Dumper;
    print Dumper(\%{$JKFlow::mylist});

	use Data::Dumper;
	print "Data:".Dumper(%JKFlow::mylist)."\n";
    reporttorrdfiles($self,"",\%JKFlow::mylist);

    if (! -d $JKFlow::OUTDIR."/total_router" ) {
    mkdir($JKFlow::OUTDIR."/total_router",0755);
    }
    reporttorrdfiles($self,"/total_router",\%{$JKFlow::mylist{'total_router'}});
    
    if (! -d $JKFlow::OUTDIR."/total_subnet" ) {
    mkdir($JKFlow::OUTDIR."/total_subnet",0755);
    }
    reporttorrdfiles($self,"/total_subnet",\%{$JKFlow::mylist{'total_subnet'}});

    foreach my $router (keys %{$JKFlow::mylist{'router'}}) {
        ($routerdir=$JKFlow::mylist{'router'}{$router}{'name'}) =~ s/\//_/g;
        print "Router:$router , Routerdir:$routerdir \n";
	if (! -d $JKFlow::OUTDIR . "/router_$routerdir" ) {
	    mkdir($JKFlow::OUTDIR . "/router_$routerdir",0755);
	}
    	reporttorrdfiles($self,"/router_".$routerdir,\%{$JKFlow::mylist{'router'}{$router}});
    }

    foreach my $subnet (keys %{$JKFlow::mylist{'subnet'}}) {
        ($subnetdir=$subnet) =~ s/\//_/g;
	if (! -d $JKFlow::OUTDIR ."/subnet_$subnetdir" ) {
	    mkdir($JKFlow::OUTDIR ."/subnet_$subnetdir",0755);
	}
     	reporttorrdfiles($self,"/subnet_".$subnetdir,\%{$JKFlow::mylist{'subnet'}{$subnet}});
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
