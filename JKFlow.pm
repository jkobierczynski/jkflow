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

	if (defined $config->{router}{total_router}) {
		$JKFlow::mylist{'total_router'} = {};
	}		
	foreach my $router (keys %{$config->{routers}{router}}) {
		my $routerip = $config->{routers}{router}{$router}{ipaddress};
		$JKFlow::mylist{'router'}{$routerip}{'name'} = $router;
		#foreach my $application (keys %{$config->{routers}{router}{$router}{application}{service}}) {
		#	pushServices(
		#		$config->{routers}{router}{$router}{application}{service}{$application}{content},
		#		\%{$JKFlow::mylist{'router'}{$routerip}{'application'}{$application}});
		#}
		pushServices(
			$config->{routers}{router}{$router}{services},
			\%{$JKFlow::mylist{'router'}{$routerip}{'service'}});
		pushProtocols(
			$config->{routers}{router}{$router}{protocols},
			\%{$JKFlow::mylist{'router'}{$routerip}{'protocol'}});
		pushApplications(
			$config->{routers}{router}{$router}{direction},
			\%{$JKFlow::mylist{'router'}{$routerip}{direction}});
		if (defined $config->{routers}{router}{$router}{tos}) {
			$JKFlow::mylist{'router'}{$routerip}{tos}={};
		}
		if (defined $config->{routers}{router}{$router}{total}) {
			$JKFlow::mylist{'router'}{$routerip}{total}={};
		}
	}

	if (defined $config->{subnet}{total_subnet}) {
		$JKFlow::mylist{'total_subnet'} = {};
	}		
	foreach my $subnet (keys %{$config->{subnets}{subnet}}) {
		$JKFlow::SUBNETS->add_string($subnet);
		#foreach my $application (keys %{$config->{subnets}{subnet}{$subnet}{application}{service}}) {
		#	pushServices(
		#		$config->{subnets}{subnet}{$subnet}{application}{service}{$application}{content},
		#		\%{$JKFlow::mylist{'subnet'}{$subnet}{'application'}{$application}});
		#}
		pushServices(
			$config->{subnets}{subnet}{$subnet}{services},
			\%{$JKFlow::mylist{'subnet'}{$subnet}{'service'}});
		pushProtocols(
			$config->{subnets}{subnet}{$subnet}{protocols},
			\%{$JKFlow::mylist{'subnet'}{$subnet}{'protocol'}});
		pushApplications(
			$config->{subnets}{subnet}{$subnet}{direction},
			\%{$JKFlow::mylist{'subnet'}{$subnet}{direction}});
		if (defined $config->{subnets}{subnet}{$subnet}{tos}) {
			$JKFlow::mylist{'subnet'}{$subnet}{tos}={};
		}
		if (defined $config->{subnets}{subnet}{$subnet}{total}) {
			$JKFlow::mylist{'subnet'}{$subnet}{total}={};
		}
	}

	foreach my $network (keys %{$config->{networks}{network}}) {
		pushApplications(
			$config->{networks}{network}{$network}{direction},
			\%{$JKFlow::mylist{'network'}{$network}{direction}});
#		foreach my $application (keys %{$config->{networks}{network}{$network}{application}{service}}) {
#			$JKFlow::mylist{'network'}{$network}{'application'}{$application}{'fromsubnet'}=
#				new Net::Patricia || die "Could not create a trie ($!)\n";
#			$JKFlow::mylist{'network'}{$network}{'application'}{$application}{'fromsubnet'}->add_string(
#				$config->{networks}{network}{$network}{application}{fromsubnet});
#			$JKFlow::mylist{'network'}{$network}{'application'}{$application}{'tosubnet'}=
#				new Net::Patricia || die "Could not create a trie ($!)\n";
#			$JKFlow::mylist{'network'}{$network}{'application'}{$application}{'tosubnet'}->add_string(
#				$config->{networks}{network}{$network}{application}{tosubnet});
#			pushServices(
#				$config->{networks}{network}{$network}{application}{service}{$application}{content},
#				\%{$JKFlow::mylist{'network'}{$network}{'application'}{'service'}{$application}});
#			pushApplications(
#				$config->{networks}{network}{$network}{application},
#				\%{$JKFlow::mylist{'network'}{$network}{'application'}});
#		}
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

	use Data::Dumper;
	print Dumper(%JKFlow::mylist)."\n";


#    open(FH,$file) || die "Could not open $file ($!)\n";

#    while(<FH>) {
#	s/\#.*$//;		# Strip out everything after a #
#	next if /^\s*$/;	# Skip blank lines

#	if (/^\s*Subnet (\d+\.\d+\.\d+\.\d+\/\d+)\s*(.*)$/) {
#	    # Stick this entry into our trie
#	    $subnet=$1;
#	    $JKFlow::SUBNETS->add_string($subnet);
#            $JKFlow::mysubnetlist{'subnet'}{$subnet} = {};
#            print "Subnet: $1 Ports: $2\n";
#            $JKFlow::myalllist{'total_subnet'}{'subnet'}{$subnet}=1;
#            foreach $current (split(/,/,$2)) {
#                # Parse each item
#                if ($current =~ /(\S+)\s*\/\s*(\S+)/) {
#                    $srv   = $1;
#                    $proto = $2;
#
#                    if ($proto !~ /\d+/) { # Not an integer! Try getprotobyname
#                        $tmp = getprotobyname($proto) ||
#                            die "Unknown protocol $proto on line $.\n";
#                        $proto = $tmp;
#			#$JKFlow::mysubnetlist{'subnet'}{$subnet}{'protocol'}{$proto}{'total'} = {};
#			$JKFlow::mysubnetlist{'subnet'}{$subnet}{'protocol'}{$proto} = {};
#                    }
#
#                    if ($srv =~ /(\d+)-?(\d+)?/) { # Numeric or range
#                        $start = $1;
#                        $end = (defined($2)) ? $2 :$start;
#
#                        die "Bad range $start - $end on line $.\n" if
#                            ($end < $start);
#
#                        for($i=$start;$i<=$end;$i++) {
#                            #$JKFlow::mysubnetlist{$subnet}{$proto}{$i} = {}; # Save all these ports
#                            $JKFlow::mysubnetlist{'subnet'}{$subnet}{'service'}{$proto}{$i} = {}; # Save all these ports
#                        }
#                    } else {    # Symbolic or bad?
#                        if ($srv !~ /\d+/) { # Not an integer?
#                            # Try getservbyname
#                            $tmp = getservbyname($srv,
#                                                 getprotobynumber($proto)) ||
#                             die "Unknown service $srv on line $.\n";
#
#                            $srv = $tmp;
#                        }
#                        $JKFlow::mysubnetlist{'subnet'}{$subnet}{'service'}{$proto}{$srv} = {};
#                    }
#                } else {
#                    die "Bad Service item $current on line $.\n";
#                }
#
#	    }
#	} elsif (/^\s*Router\s+(\d+\.\d+\.\d+\.\d+)\s*(\S+)\s*(.*)$/) {
#            $router=$1;
#	    $JKFlow::myrouterlist{$router}{'name'}=$2;
#            $JKFlow::myalllist{'total_router'}{'router'}{$router}=1;
#            foreach $current (split(/,/,$3)) {
#                # Parse each item
#                if ($current =~ /(\S+)\s*\/\s*(\S+)/) {
#                    $srv   = $1;
#                    $proto = $2;
#
#                    if ($proto !~ /\d+/) { # Not an integer! Try getprotobyname
#                        $tmp = getprotobyname($proto) ||
#                            die "Unknown protocol $proto on line $.\n";
#                        $proto = $tmp;
#                        $JKFlow::myrouterlist{'router'}{$router}{'protocol'}{$proto} = {};
#                        #$JKFlow::myrouterlist{$router}{'tos'} = {};
#                        #$JKFlow::myrouterlist{$router}{'multicast'} = {};
#                    }
#
#                    if ($srv =~ /(\d+)-?(\d+)?/) { # Numeric or range
#                        $start = $1;
#                        $end = (defined($2)) ? $2 :$start;
#
#                        die "Bad range $start - $end on line $.\n" if
#                            ($end < $start);
#
#                        for($i=$start;$i<=$end;$i++) {
#                            $JKFlow::myrouterlist{'router'}{$router}{'service'}{$proto}{$i} = {}; # Save all these ports
#                        }
#                    } else {    # Symbolic or bad?
#                        if ($srv !~ /\d+/) { # Not an integer?
#                            # Try getservbyname
#                            $tmp = getservbyname($srv,
#                                                 getprotobynumber($proto)) ||
#                             die "Unknown service $srv on line $.\n";
#
#                            $srv = $tmp;
#                        }
#                        $JKFlow::myrouterlist{'router'}{$router}{'service'}{$proto}{$srv} = {};
#                    }
#                } else {
#                    die "Bad Service item $current on line $.\n";
#                }
#
#            }
#
#	} elsif (/^\s*Network\s+(\S+)\s*(.*)$/) {
#	    $networkname = $1;
#	    $label = $2;
#            print "Network :".$networkname. "lijn :".$label."\n";
#            foreach $current (split(/,/,$2)) {
#                if ($current =~ /(\d+\.\d+\.\d+\.\d+\/\d+)/) {
#			$JKFlow::myalllist{'network'}{$networkname}{'subnet'}{$current}=1;
#		}
#                elsif ($current =~ /(\d+\.\d+\.\d+\.\d+)/) {
#			$JKFlow::myalllist{'network'}{$networkname}{'router'}{$current}=1;
#		}
#	    }
#	} elsif (/\s*Multicast\s*$/) {
#	    $JKFlow::multicast = 1;
#	} elsif (/^\s*Service\s+(\S+)\s+(\S+)\s*$/) {
#	    $txt   = $1;
#	    $label = $2;
#
#	    # A Service is one or more port/proto ranges, separated by ,'s
#	    foreach $current (split(/,/,$txt)) {
#		# Parse each item
#		if ($current =~ /(\S+)\s*\/\s*(\S+)/) {
#		    $srv   = $1;
#		    $proto = $2;
#
#		    if ($proto !~ /\d+/) { # Not an integer! Try getprotobyname
#			$tmp = getprotobyname($proto) || 
#			    die "Unknown protocol $proto on line $.\n";
#			$proto = $tmp;
#			$JKFlow::myalllist{'protocol'}{$tmp} = {};
#		    }
#
#		    if ($srv =~ /(\d+)-?(\d+)?/) { # Numeric or range
#			$start = $1;
#			$end = (defined($2)) ? $2 :$start;
#
#			die "Bad range $start - $end on line $.\n" if
#			    ($end < $start);
#
#			for($i=$start;$i<=$end;$i++) {
#			    $JKFlow::myalllist{'service'}{$proto}{$i} = {}; # Save all these ports
#                            $JKFlow::SERVICES{$proto}{$i} = $label; 
#			}
#		    } else {	# Symbolic or bad?
#			if ($srv !~ /\d+/) { # Not an integer? 
#			    # Try getservbyname
#			    $tmp = getservbyname($srv,
#						 getprotobynumber($proto)) ||
#			     die "Unknown service $srv on line $.\n";
#
#			    $srv = $tmp;
#			}
#			$JKFlow::myalllist{'service'}{$proto}{$srv} = {};
#                        $JKFlow::SERVICES{$proto}{$srv} = $label; 
#		    }
#		} else {
#		    die "Bad Service item $current on line $.\n";
#		}
#	    }
#	} elsif (/^\s*TOS\s+(\S+)\s+(\S+)\s*$/) {
#	    $txt   = $1;
#	    $label = $2;
#
#	    $hr = { };		# New hashref
#	    
#	    # a TOS value can be one or more ranges of ints, separated by ,'s
#	    foreach $current (split(/,/,$txt)) {
#		# parse each item
#		if ($current =~ /(\d+)-?(\d+)?/) {	# A range
#		    $start = $1;
#		    $end = (defined($2)) ? $2 :$start;
#
#		    die "Bad range $start - $end on line $.\n" if
#			($end < $start);
#
#		    die "Bad TOS value $start on line $.\n" if
#			(($start < 0) || ($start > 255));
#
#		    die "Bad TOS value $end on line $.\n" if
#			(($end < 0) || ($end > 255));
#
#		    for($i=$start;$i<=$end;$i++) {
#			$hr->{$i} = 1; # Save all these ports
#		    }		    
#		} else {
#		    die  "Bad TOS item $current on line $.\n";
#		}
#	    }
#	    $JKFlow::TOS{$label} = $hr;
#	} elsif (/^\s*Scoreboard\s+(\d+)\s+(\S+)\s+(\S+)\s*$/) {
#	    $num = $1;
#	    $dir = $2;
#	    $current = $3;
#	    
#	    eval "use HTML::Table";
#	    die "$@" if $@;
#
#	    $JKFlow::scorekeep = $num;
#	    $JKFlow::scoredir  = $dir;
#	    $JKFlow::scorepage = $current;
#	} elsif (/^\s*AggregateScore\s+(\d+)\s+(\S+)\s+(\S+)\s*$/) {
#	    $num = $1;
#	    $dir = $2;
#	    $current = $3;
#	    
#	    $JKFlow::aggscorekeep = $num;
#	    $JKFlow::aggscorefile  = $dir;
#	    $JKFlow::aggscoreout = $current;
#	} elsif (/^\s*Protocol\s+(\S+)\s*(\S+)?\s*$/) {
#	    $proto = $1;
#	    $label = $2;
#
#	    if ($proto !~ /\d+/) { # non-numeric protocol name
#		# Try resolving
#		$tmp = getprotobyname($proto) || 
#		    die "Unknown protocol $proto on line $.\n";
#	        $JKFlow::myalllist{'protocol'}{$tmp} = {};
#		if (defined($label)) {
#		    $JKFlow::PROTOCOLS{$tmp} = $label;
#		} else {
#		    $JKFlow::PROTOCOLS{$tmp} = $proto;
#		}
#	    } else {
#	        $JKFlow::myalllist{'protocol'}{$proto} = {};
#		if (defined($label)) {
#		    $JKFlow::PROTOCOLS{$proto} = $label;
#		} else {
#		    $JKFlow::PROTOCOLS{$proto} = $proto;
#		}
#	    }
#	    $JKFlow::myalllist{'protocol'}{$proto} = {};
#	    
#	} elsif (/^\s*OutputDir\s+(\S+)\s*$/) {
#	    $JKFlow::OUTDIR = $1;
#	} else {
#	    die "Invalid line $. in $file\n\t$_\n";
#	}
#    }
#
#    close(FH);
#    use Data::Dumper;
#    print Dumper($JKFlow::mylist);
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

	use Data::Dumper;
	print "refxml=".Dumper($refxml)."\n";
	print "ref=".Dumper($ref)."\n";
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
						$ref->{$refxml->{'name'}}{'application'}{$application}{$proto}{$i} = {};
					}
				} else {
					if ($srv !~ /\d+/) {
						$tmp = getservbyname($srv, getprotobynumber($proto)) || die "Unknown service $srv on line $.\n";
						$srv = $tmp;
					}
					$ref->{$refxml->{'name'}}{'application'}{$application}{$proto}{$srv} = {};
				}
			} else {
				die "Bad Service Item $current on line $.\n";
			}
		}	
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

    # First, are we inbound or outbound?
    if ($JKFlow::SUBNETS->match_integer($dstaddr)) {
        # If the destination is in inside, this is an inbound flow
        $which = 'in';
    } else {
        # The destination for this flow is not in SUBNETS; it is outbound
        $which = 'out';
    }

    if (($dstaddr & $JKFlow::MCAST_MASK) == $JKFlow::MCAST_NET) {
        countmulticasts(\%{$JKFlow::mylist});
	if ($subnet = $JKFlow::SUBNETS->match_integer($srcaddr)) {
	    $which = 'out';
            countmulticasts(\%{$JKFlow::mylist{'subnet'}{$subnet}});
	} else {
	    $which = 'in';
	}
	return 1;	
    } 
   countpackets(\%JKFlow::mylist);

   if (defined $JKFlow::mylist{'router'}{$exporterip}) 
      {
      countpackets(\%{$JKFlow::mylist{'router'}{$exporterip}});
      countmulticasts(\%{$JKFlow::mylist{'router'}{$exporterip}});
      }

   if (($subnet = $JKFlow::SUBNETS->match_integer($dstaddr)) 
	|| ($subnet = $JKFlow::SUBNETS->match_integer($srcaddr)))
      {
      countpackets(\%{$JKFlow::mylist{'subnet'}{$subnet}});
      }
    return 1;
}

sub countpackets {
    my $payload = shift;
    my $typeos;
    $payload->{'total'}{$which}{'flows'} ++;
    $payload->{'total'}{$which}{'bytes'} += $bytes;
    $payload->{'total'}{$which}{'pkts'} += $pkts;
    if ($tos == 0) {
	$typeos="normal";
    } else {
        $typeos="other"; 
    }
    $payload->{'tos'}{$typeos}{$which}{'flows'} ++;
    $payload->{'tos'}{$typeos}{$which}{'bytes'} += $bytes;
    $payload->{'tos'}{$typeos}{$which}{'pkts'} += $pkts;
    if (defined $payload->{'protocol'}{$protocol}) {
      $payload->{'protocol'}{$protocol}{'total'}{$which}{'flows'}++;
      $payload->{'protocol'}{$protocol}{'total'}{$which}{'bytes'} += $bytes;
      $payload->{'protocol'}{$protocol}{'total'}{$which}{'pkts'} += $pkts;
      $payload->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{'flows'}++;
      $payload->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{'bytes'} += $bytes;
      $payload->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{'pkts'} += $pkts;
    }
    if (defined $payload->{'service'}{$protocol}{$srcport}) 
      {
      $payload->{'service'}{$protocol}{$srcport}{'src'}{$which}{'flows'}++;
      $payload->{'service'}{$protocol}{$srcport}{'src'}{$which}{'bytes'} += $bytes;
      $payload->{'service'}{$protocol}{$srcport}{'src'}{$which}{'pkts'} += $pkts;
      }
    if (defined $payload->{'service'}{$protocol}{$dstport}) 
      {
      $payload->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'flows'}++;
      $payload->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'bytes'} += $bytes;
      $payload->{'service'}{$protocol}{$dstport}{'dst'}{$which}{'pkts'} += $pkts;
      }
}

sub countmulticasts {
    my $payload = shift;
    my $typeos;
    $payload->{'multicast'}{'total'}{$which}{'flows'}++;
    $payload->{'multicast'}{'total'}{$which}{'bytes'} += $bytes;
    $payload->{'multicast'}{'total'}{$which}{'pkts'} += $pkts;
    if ($tos == 0) {
	$typeos="normal";
    } else {
        $typeos="other"; 
    }
    $payload->{'multicast'}{'tos'}{$typeos}{$which}{'flows'}++;
    $payload->{'multicast'}{'tos'}{$typeos}{$which}{'bytes'} += $bytes;
    $payload->{'multicast'}{'tos'}{$typeos}{$which}{'pkts'} += $pkts;
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
         foreach my $protocol (keys %{$addref->{'protocol'}}) { 
         	$sumref->{'protocol'}{$protocol}{'total'}{$which}{$type} 
			+= $addref->{'protocol'}{$protocol}{'total'}{$which}{$type};
		foreach my $service (keys %{$addref->{'service'}{$protocol}}) {
         	$sumref->{'service'}{$protocol}{$service}{'src'}{$which}{$type} 
			+= $addref->{'service'}{$protocol}{$service}{'src'}{$which}{$type};
         	$sumref->{'service'}{$protocol}{$service}{'dst'}{$which}{$type} 
			+= $addref->{'service'}{$protocol}{$service}{'dst'}{$which}{$type};
                }
         }
         $sumref->{'multicast'}{'total'}{$which}{$type} 
		+= $addref->{'multicast'}{'total'}{$which}{$type};
         foreach my $typeos ('normal','other') {
	    $sumref->{'tos'}{$typeos}{$which}{$type}
			+= $addref->{'tos'}{$typeos}{$which}{$type};
            foreach my $protocol (keys %{$addref->{'protocol'}}) {
         	$sumref->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{$type}
			+= $addref->{'protocol'}{$protocol}{'tos'}{$typeos}{$which}{$type};
            }
            $sumref->{'multicast'}{'tos'}{$typeos}{$which}{$type} 
 		+= $addref->{'multicast'}{'tos'}{$typeos}{$which}{$type};
         }
         $sumref->{'total'}{$which}{$type} 
		+= $addref->{'total'}{$which}{$type};
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
        #use Data::Dumper;
        #print Dumper(\%{$JKFlow::mylist{'network'}{$network}});
    }  

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
