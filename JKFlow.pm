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

$JKFlow::AGGSCOREKEEP = 10;				
#my($scorepage) = 'index.html';	# The link to the current page
#my($aggscorekeep) = 10;		# Do not create an overall rankings file

$JKFlow::NUMKEEP = 50;		# How many aggregates to keep

my(%myservices);
my(%myalllist);
my($subnet);
my($config);

my($flowrate) = 1;
my($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);

$JKFlow::directionroutersgroupsonly = 0;	# Are there directions with only routergroup attributes?
$JKFlow::servicescounted = 0;			# Used for counting services not counted in other directions.
$JKFlow::multicast = 0;				# Do multicast? Default no.

# Multicast address spec's, taken from CampusIO
$JKFlow::MCAST_NET  = unpack('N', inet_aton('224.0.0.0'));
$JKFlow::MCAST_MASK = unpack('N', inet_aton('240.0.0.0'));

$JKFlow::SUBNETS = new Net::Patricia || die "Could not create a trie ($!)\n";
$JKFlow::trie = new Net::Patricia || die "Could not create a trie ($!)\n";
&parseConfig;	# Read our config file

sub parseConfig {
    my($ip,$mask,$srv,$proto,$label,$tmp,$txt);
    my($num,$dir,$current,$start,$end,$i,$subnet,$router,$networkname);

	use XML::Simple;
	$config=XMLin('/usr/local/bin/JKFlow.xml',
		forcearray=>[	'router','routergroup','interface','subnet','site','network',
				'direction','application','defineset','set','report']);

	$JKFlow::RRDDIR = $config->{rrddir};
	$JKFlow::SCOREDIR = $config->{scoredir};
	if (defined $config->{sampletime}) {
		$JKFlow::SAMPLETIME=$config->{sampletime};
	} else {
		$JKFlow::SAMPLETIME=300;
	}
	
	
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
		generateCountPackets(\%{$JKFlow::mylist{all}});
	}

	if (defined $config->{routergroups}) {
		if (defined $config->{routergroups}{routergroup}){
			foreach my $routergroup (keys %{$config->{routergroups}{routergroup}}) {
				print "Routergroup: $routergroup\n";
				foreach my $exporter (@{$config->{routergroups}{routergroup}{$routergroup}{router}}) {
					print "Exporter: ".$exporter->{exporter}.", ";
					if (defined $exporter->{interface}) {
						print "interface: ".$exporter->{interface};
						my $list=[];
						if (defined $JKFlow::mylist{routers}{router}{$exporter->{exporter}}{$exporter->{interface}}{routergroups}) {
							push @{$list},@{$JKFlow::mylist{routers}{router}{$exporter->{exporter}}{$exporter->{interface}}{routergroups}};
						}
						push @{$list},$routergroup;
						$JKFlow::mylist{routers}{router}{$exporter->{exporter}}{$exporter->{interface}}{routergroups}=$list;
					} 
					if (defined $exporter->{localsubnets}) {
						print "localsubnets: ".$exporter->{localsubnets};
						my $list=[];
						if (defined $JKFlow::mylist{routers}{router}{$exporter->{exporter}}{routergroups}) {
							push @{$list},@{$JKFlow::mylist{routers}{router}{$exporter->{exporter}}{routergroups}};
						}
						push @{$list},$routergroup;
						$JKFlow::mylist{routers}{router}{$exporter->{exporter}}{routergroups}=$list;
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

	pushDirections (
		\%{$config->{directions}{direction}},
		\%{$JKFlow::mylist{direction}});

	pushDirections3( \@{$JKFlow::mylist{'triesubnets'}}, $JKFlow::trie );
	
	createwanted();
}

sub parseDirection {
my $refxml=shift;
my $ref=shift;

	if (defined $refxml->{set}) {
		foreach my $set (keys %{$refxml->{set}}) {
			print "parseDirection: ".$set."\n";
			parseDirection(
				\%{$config->{definesets}{defineset}{$set}},
				$ref);
		}
	}
	pushServices(
		$refxml->{services},
		\%{$ref});
	if (defined $refxml->{otherservices}) {
		$ref->{application}{other}={};
	}
	pushProtocols(
		$refxml->{protocols},
		\%{$ref});
	if (defined $refxml->{otherprotocols}) {
		$ref->{protocol}{other}={};
	}
	if (defined $refxml->{direction}) {
		if (!defined $ref->{direction}) {
			$ref->{direction}={};
		}
		pushDirections(
			$refxml->{direction},
			\%{$ref->{direction}});
		}
	if (defined $refxml->{application}) {
		if (!defined $ref->{application}) {
			$ref->{application}={};
		}
		pushApplications(
			$refxml->{application},
			\%{$ref});
	}
	if (defined $refxml->{ftp} && !defined $ref->{ftp}) {
		$ref->{ftp}={};
	}
	if (defined $refxml->{multicast} && !defined $ref->{multicast}) {
		$ref->{multicast}={};
	}
	if (defined $refxml->{tos} && !defined $ref->{tos}) {
		$ref->{tos}={};
	}
	if (defined $refxml->{total} && !defined $ref->{total}) {
		$ref->{total}={};
	}
	if (defined $refxml->{monitor} && $refxml->{monitor} == "yes" && !defined $ref->{monitor}) {
		$ref->{monitor}="yes";
	}
	if (defined $refxml->{scoreboard}) {
		if (defined $refxml->{scoreboard}{hosts} && $refxml->{scoreboard}{hosts} =="1" && !defined $ref->{scoreboard}{hosts}) {
			$ref->{scoreboard}{hosts}{all}={};
		}
		if (defined $refxml->{scoreboard}{ports} && $refxml->{scoreboard}{ports}=="1" && !defined $ref->{scoreboard}{ports}) {
			$ref->{scoreboard}{ports}{all}={};
		}
		if (defined $refxml->{scoreboard}{latesthosts}) {
			$ref->{scoreboard}{hosts}{all}={};
			$ref->{scoreboard}{latest}{hosts}=$refxml->{scoreboard}{latesthosts};
			print "Scorepage hosts is $ref->{scoreboard}{latest}{hosts}\n";
		}
		if (defined $refxml->{scoreboard}{latestports}) {
			$ref->{scoreboard}{ports}{all}={};
			$ref->{scoreboard}{latest}{ports}=$refxml->{scoreboard}{latestports};
			print "Scorepage ports is $ref->{scoreboard}{latest}{ports}\n";
		}
		if (defined $refxml->{scoreboard}{report}) {
			foreach my $report (@{$refxml->{scoreboard}{report}}) {
				if (defined $report->{hostsbase}) {
					if (!defined $ref->{scoreboard}{hosts}) { $ref->{scoreboard}{hosts}={}; }
					push @{$ref->{scoreboard}{aggregate}{hosts}{report}},
					{	'count' => $report->{count},
						'filenamebase' => $report->{hostsbase},
						'scorekeep' => (defined $report->{scorekeep} ? $report->{scorekeep} : 10), 
						'numkeep' => (defined $report->{numkeep} ? $report->{numkeep} : 50) };
				}
				if (defined $report->{portsbase}) {
					if (!defined $ref->{scoreboard}{ports}) { $ref->{scoreboard}{ports}={}; }
					push @{$ref->{scoreboard}{aggregate}{ports}{report}},
					{	'count' => $report->{count},
						'filenamebase' => $report->{portsbase},
						'scorekeep' => (defined $report->{scorekeep} ? $report->{scorekeep} : 10), 
						'numkeep' => (defined $report->{numkeep} ? $report->{numkeep} : 50) };
				}
			}
		}
	}
	if (defined $refxml->{scoreboardother}) {
		if (defined $refxml->{scoreboardother}{hosts} && $refxml->{scoreboardother}{hosts} =="1" && !defined $ref->{scoreboardother}{hosts}) {
			$ref->{scoreboardother}{hosts}{all}={};
		}
		if (defined $refxml->{scoreboardother}{ports} && $refxml->{scoreboardother}{ports}=="1" && !defined $ref->{scoreboardother}{ports}) {
			$ref->{scoreboardother}{ports}{all}={};
		}
		if (defined $refxml->{scoreboardother}{hosts} && defined $refxml->{scoreboardother}{latesthosts}) {
			$ref->{scoreboardother}{hosts}{all}={};
			$ref->{scoreboardother}{latest}{hosts}=$refxml->{scoreboardother}{latesthosts};
			print "Scorepage hosts is $ref->{scoreboardother}{latest}{hosts}\n";
		}
		if (defined $refxml->{scoreboardother}{ports} && defined $refxml->{scoreboardother}{latestports}) {
			$ref->{scoreboardother}{ports}{all}={};
			$ref->{scoreboardother}{latest}{ports}=$refxml->{scoreboardother}{latestports};
			print "Scorepage ports is $ref->{scoreboardother}{latest}{ports}\n";
		}
		if (defined $refxml->{scoreboardother}{report}) {
			foreach my $report (@{$refxml->{scoreboardother}{report}}) {
				if (defined $report->{hostsbase}) {
					if (!defined $ref->{scoreboardother}{hosts}) { $ref->{scoreboardother}{hosts}={}; }
					push @{$ref->{scoreboardother}{aggregate}{hosts}{report}},
					{	'count' => $report->{count},
						'filenamebase' => $report->{hostsbase},
						'scorekeep' => (defined $report->{scorekeep} ? $report->{scorekeep} : 10), 
						'numkeep' => (defined $report->{numkeep} ? $report->{numkeep} : 50) };
				}
				if (defined $report->{portsbase}) {
					if (!defined $ref->{scoreboardother}{ports}) { $ref->{scoreboardother}{ports}={}; }
					push @{$ref->{scoreboardother}{aggregate}{ports}{report}},
					{	'count' => $report->{count},
						'filenamebase' => $report->{portsbase},
						'scorekeep' => (defined $report->{scorekeep} ? $report->{scorekeep} : 10), 
						'numkeep' => (defined $report->{numkeep} ? $report->{numkeep} : 50) };
				}
			}
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
		$ref->{protocol}{$proto} = {};
	}
}

sub pushServices {
my $refxml=shift;
my $ref=shift;
my ($srv,$proto,$start,$end,$tmp,$i,$servsym,$protosym);

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
					$protosym = getprotobynumber($proto) ? getprotobynumber($proto) : $proto;
					$servsym = getservbyport($i,$protosym) ? getservbyport($i,$protosym) : $i;
					$ref->{'application'}{$protosym.'_'.$servsym} = {};
					$ref->{'service'}{$proto}{$i} = \%{$ref->{'application'}{$protosym.'_'.$servsym}};
				}
			} else {
				if ($srv !~ /\d+/) {
					$tmp = getservbyname($srv, getprotobynumber($proto)) || die "Unknown service $srv on line $.\n";
					$srv = $tmp;
				}
				$protosym = getprotobynumber($proto) ? getprotobynumber($proto) : $proto;
				$servsym = getservbyport($srv,$protosym) ? getservbyport($srv,$protosym) : $srv;
				$ref->{'application'}{$protosym.'_'.$servsym} = {};
				$ref->{'service'}{$proto}{$srv} = \%{$ref->{'application'}{$protosym.'_'.$servsym}};
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
		$ref->{'application'}{$application} = {};
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
						$ref->{'service'}{$proto}{$i} = \%{$ref->{'application'}{$application}};
					}
				} else {
					if ($srv !~ /\d+/) {
						$tmp = getservbyname($srv, getprotobynumber($proto)) || die "Unknown service $srv on line $.\n";
						$srv = $tmp;
					}
					$ref->{'service'}{$proto}{$srv} = \%{$ref->{'application'}{$application}};
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
				push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'included' };
				${$ref->{$direction}{'fromsubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'tosubnets'}) { 
			${$ref->{$direction}{'tosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'tosubnets'})) {
				print "Adding tosubnets subnet $subnet \n";
				push @{$tosubnets}, $subnet;
				push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'included' };
				${$ref->{$direction}{'tosubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'nofromsubnets'}) {
			${$ref->{$direction}{'nofromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'nofromsubnets'})) {
				print "Adding nofromsubnets subnet $subnet \n";
				push @{$nofromsubnets}, $subnet;
				push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'excluded' };
				${$ref->{$direction}{'nofromsubnets'}}->add_string($subnet);
			}
		}
		if (defined $refxml->{$direction}{'notosubnets'}) { 
			${$ref->{$direction}{'notosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			foreach my $subnet (split(/,/,$refxml->{$direction}{'notosubnets'})) {
				print "Adding notosubnets subnet $subnet \n";
				push @{$notosubnets}, $subnet;
				push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'excluded' };
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
			print "Adding fromsubnets ".$refxml->{$direction}{from}."\n";
			foreach my $site (split(/,/,$refxml->{$direction}{from})) {
				print "Adding fromsite $site \n";
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{subnets})) {
					print "Adding fromsubnets subnet $subnet \n";
					push @{$fromsubnets}, $subnet;
					push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'included' };
					${$ref->{$direction}{'fromsubnets'}}->add_string($subnet);
				}
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{nosubnets})) {
					print "Adding nofromsubnets subnet $subnet \n";
					push @{$nofromsubnets}, $subnet;
					push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'excluded' };
					${$ref->{$direction}{'nofromsubnets'}}->add_string($subnet);
				}	
			}
		}

		if (defined $refxml->{$direction}{"nofrom"}) {
			if (!defined $ref->{$direction}{'fromsubnets'}) {
				${$ref->{$direction}{'fromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			}
			if (!defined $ref->{$direction}{'nofromsubnets'}) {
				${$ref->{$direction}{'nofromsubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			}
			print "Adding nofromsubnets ".$refxml->{$direction}{nofrom}."\n";
			foreach my $site (split(/,/,$refxml->{$direction}{nofrom})) {
				print "Adding nofromsite $site \n";
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{nosubnets})) {
					print "Adding fromsubnets subnet $subnet \n";
					push @{$fromsubnets}, $subnet;
					push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'included' };
					${$ref->{$direction}{'fromsubnets'}}->add_string($subnet);
				}	
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{subnets})) {
					print "Adding nofromsubnets subnet $subnet \n";
					push @{$nofromsubnets}, $subnet;
					push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'excluded' };
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
			print "Adding tosubnets ".$refxml->{$direction}{to}."\n";
			foreach my $site (split(/,/,$refxml->{$direction}{to})) {
				print "Adding tosite $site \n";
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{subnets})) {
					print "Adding tosubnets subnet $subnet \n";
					push @{$tosubnets}, $subnet;
					push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'included' };
					${$ref->{$direction}{'tosubnets'}}->add_string($subnet);
				}
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{nosubnets})) {
					print "Adding notosubnets subnet $subnet \n";
					push @{$notosubnets}, $subnet;
					push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'excluded' };
					${$ref->{$direction}{'notosubnets'}}->add_string($subnet);
				}	
			}
		}

		if (defined $refxml->{$direction}{"noto"}) {
			if (!defined $ref->{$direction}{'tosubnets'}) {
				${$ref->{$direction}{'tosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			}
			if (!defined $ref->{$direction}{'notosubnets'}) {
				${$ref->{$direction}{'notosubnets'}}=new Net::Patricia || die "Could not create a trie ($!)\n";
			}
			print "Adding notosubnets ".$refxml->{$direction}{noto}."\n";
			foreach my $site (split(/,/,$refxml->{$direction}{noto})) {
				print "Adding tosite $site \n";
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{nosubnets})) {
					print "Adding tosubnets subnet $subnet \n";
					push @{$tosubnets}, $subnet;
					push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'included' };
					${$ref->{$direction}{'tosubnets'}}->add_string($subnet);
				}
				foreach my $subnet (split(/,/,$config->{sites}{site}{$site}{subnets})) {
					print "Adding notosubnets subnet $subnet \n";
					push @{$notosubnets}, $subnet;
					push @{$JKFlow::mylist{triesubnets}}, { subnet=>$subnet, type=>'excluded' };
					${$ref->{$direction}{'notosubnets'}}->add_string($subnet);
				}	
			}
		}

		# If nofrom attributes, but not any from attribute defined, assume from="0.0.0.0/0"
		if (@{$nofromsubnets} > 0 && @{$fromsubnets} == 0) {
			print "Adding fromsubnet 0.0.0.0/0 implicit \n";
			push @{$fromsubnets}, "0.0.0.0/0";
			push @{$JKFlow::mylist{triesubnets}}, { subnet=>"0.0.0.0/0", type=>'included' };
			${$ref->{$direction}{'fromsubnets'}}->add_string("0.0.0.0/0");
		}
		# If noto attributes, but not any to attribute defined, assume to="0.0.0.0/0"
		if (@{$notosubnets} > 0 && @{$tosubnets} == 0) {
			print "Adding tosubnet 0.0.0.0/0 implicit \n";
			push @{$tosubnets}, "0.0.0.0/0"; 
			push @{$JKFlow::mylist{triesubnets}}, { subnet=>"0.0.0.0/0", type=>'included' };
			${$ref->{$direction}{'tosubnets'}}->add_string("0.0.0.0/0");
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

		if (defined $refxml->{$direction}{"routergroup"}) {
			my $routergroup=$refxml->{$direction}{"routergroup"};
			print "Direction routergroup=".$routergroup."\n";
			foreach my $exporter (@{$config->{routergroups}{routergroup}{$routergroup}{router}}) {
				print "Exporter: ".$exporter->{exporter}.", ";
				if (!defined $ref->{$direction}{router}{$exporter->{exporter}}) {
					$ref->{$direction}{router}{$exporter->{exporter}}={};
				}
				if (defined $exporter->{interface}) {
					print "interface: ".$exporter->{interface};
					$ref->{$direction}{router}{$exporter->{exporter}}{$exporter->{interface}}={};
				}
				if (defined $exporter->{localsubnets}) {
					$ref->{$direction}{router}{$exporter->{exporter}}{localsubnets}=new Net::Patricia || die "Could not create a trie ($!)\n";
					print "localsubnets: ";
					foreach my $subnet (split(/,/,$exporter->{localsubnets})) {
						print "+ subnet $subnet ";
						$ref->{$direction}{router}{$exporter->{exporter}}{localsubnets}->add_string($subnet);
					}
				}
				print "\n";
			}
			$ref->{$direction}{countfunction}=\&countFunction2;
		} else {
			$ref->{$direction}{countfunction}=\&countFunction1;
		}

		# This may have some explanation... Why don't push references of directions into $JKFlow::mylist{routergroup}
		# if any subnets are defined in the direction ? This is because in countDirections2() these directions will
		# call countFunction2 (registered here above, because these directions contains routergroup attributes) and will
		# call countPackets and countApplications by itself so we won't allow calling these functions from within the
		# router section of wanted().

		if (	defined $refxml->{$direction}{'routergroup'} &&
			!defined $refxml->{$direction}{'fromsubnets'} &&
			!defined $refxml->{$direction}{'tosubnets'} &&
			!defined $refxml->{$direction}{'nofromsubnets'} &&
			!defined $refxml->{$direction}{'notosubnets'} &&
			!defined $refxml->{$direction}{'from'} &&
			!defined $refxml->{$direction}{'to'} &&
			!defined $refxml->{$direction}{'nofrom'} &&
			!defined $refxml->{$direction}{'noto'}) {
			$JKFlow::directionroutersgroupsonly=1;
			my $list=[];
			my $routergroup=$refxml->{$direction}{"routergroup"};
			if (defined $JKFlow::mylist{routergroup}{$routergroup}) {
				push @{$list},@{$JKFlow::mylist{routergroup}{$routergroup}};
			}
			print "Assign routergroup ".$routergroup." to Direction ".$direction."\n";
			push @{$list},$ref->{$direction};
			$JKFlow::mylist{routergroup}{$routergroup}=$list;
		}

		parseDirection (\%{$refxml->{$direction}}, \%{$ref->{$direction}});
		generateCountPackets(\%{$ref->{$direction}});
		
		#use Data::Dumper;
		#print Dumper($ref->{$direction});

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

sub createwanted {
	my $createwanted='sub wanted {
	my $self = shift;

';
	if ((defined $JKFlow::mylist{'all'}) && (defined $JKFlow::mylist{'all'}{'localsubnets'})) {
	$createwanted.= <<'EOF';
	# Counting ALL
	if ($JKFlow::mylist{'all'}{'localsubnets'}->match_integer($srcaddr) &&
	   !$JKFlow::mylist{'all'}{'localsubnets'}->match_integer($dstaddr)) {
		&{$JKFlow::mylist{'all'}{countpackets}}(\%{$JKFlow::mylist{'all'}},'out');
	}
	if ($JKFlow::mylist{'all'}{'localsubnets'}->match_integer($dstaddr) &&
	   !$JKFlow::mylist{'all'}{'localsubnets'}->match_integer($srcaddr)) {
		&{$JKFlow::mylist{'all'}{countpackets}}(\%{$JKFlow::mylist{'all'}},'in');
	}
	
EOF
	}

	# Counting ALL, but with no localsubnets. Assume everything outbound
	if ((defined $JKFlow::mylist{'all'}) && (!defined $JKFlow::mylist{'all'}{'localsubnets'})) {
	$createwanted.= <<'EOF';
	&{$JKFlow::mylist{'all'}{countpackets}}(\%{$JKFlow::mylist{'all'}},'out');

EOF
	}

	if ($JKFlow::directionroutersgroupsonly == 1) {
	$createwanted.= <<'EOF';
	# Counting for Routers
	if (defined $JKFlow::mylist{routers}{router}{$exporterip}) {
		if (defined $JKFlow::mylist{routers}{router}{$exporterip}{$output_if}) {
			foreach my $routergroup ( @{$JKFlow::mylist{routers}{router}{$exporterip}{$output_if}{routergroups}}) {
				#use Data::Dumper;
				#print Dumper(%{$JKFlow::mylist{routergroup}{$routergroup}})."\n";
				foreach my $ref (@{$JKFlow::mylist{routergroup}{$routergroup}}) {
					&{$ref->{countpackets}}(\%{$ref},'out');
				}
			}
		}
		if (defined $JKFlow::mylist{routers}{router}{$exporterip}{$input_if}) {
			foreach my $routergroup ( @{$JKFlow::mylist{routers}{router}{$exporterip}{$input_if}{routergroups}}) {
				#use Data::Dumper;
				#print Dumper(%{$JKFlow::mylist{routergroup}{$routergroup}})."\n";
				foreach my $ref (@{$JKFlow::mylist{routergroup}{$routergroup}}) {
					&{$ref->{countpackets}}(\%{$ref},'in');
				}
			}
		}
		if (defined $JKFlow::mylist{routers}{router}{$exporterip}{localsubnets}) {
			if ($JKFlow::mylist{routers}{router}{$exporterip}{localsubnets}->match_integer($dstaddr) &&
			   !$JKFlow::mylist{routers}{router}{$exporterip}{localsubnets}->match_integer($srcaddr)) {
				foreach my $routergroup ( @{$JKFlow::mylist{routers}{router}{$exporterip}{routergroups}}) {
					foreach my $ref (@{$JKFlow::mylist{routergroup}{$routergroup}}) {
					&{$ref->{countpackets}}(\%{$ref},'in');
					}
				}
			}
			if ($JKFlow::mylist{routers}{router}{$exporterip}{localsubnets}->match_integer($srcaddr) &&
			   !$JKFlow::mylist{routers}{router}{$exporterip}{localsubnets}->match_integer($dstaddr)) {
				foreach my $routergroup ( @{$JKFlow::mylist{routers}{router}{$exporterip}{routergroups}}) {
					foreach my $ref (@{$JKFlow::mylist{routergroup}{$routergroup}}) {
					&{$ref->{countpackets}}(\%{$ref},'out');
					}
				}
			}
		}
	}

EOF
	}
	$createwanted.= <<'EOF';
	countDirections();
	return 1;
}
EOF
	eval $createwanted;
}

sub countFunction1($direction,$which) {
	my $direction=shift;
	my $which=shift;
	&{$direction->{countpackets}}(\%{$direction},$which);
}

sub countFunction2($direction,$which) {
	my $direction=shift;
	my $which=shift;
	if (	defined $direction->{router}{$exporterip} &&
		defined $direction->{router}{$exporterip}{$input_if}) {
			&{$direction->{countpackets}}(\%{$direction},'in');
	}
	if (	defined $direction->{router}{$exporterip} &&
		defined $direction->{router}{$exporterip}{$output_if}) {
			&{$direction->{countpackets}}(\%{$direction},'out');
	}
	if (	defined $direction->{router}{$exporterip}{localsubnets}) {
		if ($direction->{router}{$exporterip}{localsubnets}->match_integer($dstaddr) &&
		   !$direction->{router}{$exporterip}{localsubnets}->match_integer($srcaddr)) {
				&{$direction->{countpackets}}(\%{$direction},'in');
		}
		if ($direction->{router}{$exporterip}{localsubnets}->match_integer($srcaddr) &&
		   !$direction->{router}{$exporterip}{localsubnets}->match_integer($dstaddr)) {
				&{$direction->{countpackets}}(\%{$direction},'out');
		}
	}
}

sub countDirections {

	my $srcsubnets;
	my $dstsubnets;

	my $srctriematch = $JKFlow::trie->match_integer($srcaddr);
	my $dsttriematch = $JKFlow::trie->match_integer($dstaddr);

	if ((defined $srctriematch) && (defined $dsttriematch) && (defined ($srcsubnets = $srctriematch->{included})) && (defined ($dstsubnets = $dsttriematch->{included}))) {
		foreach my $srcsubnet (@{$srcsubnets}) {
			foreach my $dstsubnet (@{$dstsubnets}) {
				#print "SrcSubnet=".$srcsubnet."\n";
				#print "DstSubnet=".$dstsubnet."\n";
				if (defined $JKFlow::mylist{subnets}{$srcsubnet}{$dstsubnet}) {
					foreach $direction (@{$JKFlow::mylist{subnets}{$srcsubnet}{$dstsubnet}}) {
						my %i={},%j={};
						if (	
						(! grep { ++$i{$_} > 1 } ( @{$srctriematch->{excluded}},@{$direction->{nofromsubnets}})) && 
						(! grep { ++$j{$_} > 1 } ( @{$dsttriematch->{excluded}},@{$direction->{notosubnets}}))) {
							#print "Direction:".$direction->{ref}{name}." InputInt:".$input_if." OutputInt:".$output_if."\n";
							&{$direction->{ref}{countfunction}}(\%{$direction->{ref}},'out');
						}
					}
				}
				if (defined $JKFlow::mylist{subnets}{$dstsubnet}{$srcsubnet}) {
					foreach $direction (@{$JKFlow::mylist{subnets}{$dstsubnet}{$srcsubnet}}) {
						my %i={},%j={};
						if (	
						(! grep { ++$i{$_} > 1 } ( @{$srctriematch->{excluded}},@{$direction->{notosubnets}})) && 
						(! grep { ++$j{$_} > 1 } ( @{$dsttriematch->{excluded}},@{$direction->{nofromsubnets}}))) {
							#print "Direction:".$direction->{ref}{name}." InputInt:".$input_if." OutputInt:".$output_if."\n";
							&{$direction->{ref}{countfunction}}(\%{$direction->{ref}},'in');
						}
					}
				}
			}
		}
	}
		
	if ( defined $JKFlow::mylist{direction}{other} && !$servicecounted ) {
		#print "Counting!\n";
		&{$JKFlow::mylist{direction}{other}{countfunction}}(\%{$JKFlow::mylist{direction}{other}},'out');

	}
	$servicecounted=0;
}


sub generateCountPackets {

	my $ref=shift;
	my $countpackets='sub {
	my $ref=shift;
	my $which=shift;
	my $typeos;
	my $refref;

';

	if (defined $ref->{'total'}) {
	$countpackets.= <<'EOF';
	
	$ref->{'total'}{$which}{'flows'} ++;
	$ref->{'total'}{$which}{'bytes'} += $bytes;
	$ref->{'total'}{$which}{'pkts'} += $pkts;

EOF
	}

	if (defined $ref->{'tos'}) {
	$countpackets.= <<'EOF';
	if ($tos == 0) {
		$typeos="normal";
	} else {
		$typeos="other";
	}
	
	$ref->{'tos'}{$typeos}{$which}{'flows'} ++;
	$ref->{'tos'}{$typeos}{$which}{'bytes'} += $bytes;
	$ref->{'tos'}{$typeos}{$which}{'pkts'} += $pkts;

EOF
	}

	if (defined $ref->{'multicast'}) {
	$countpackets.= <<'EOF';
	if (($dstaddr & $JKFlow::MCAST_MASK) == $JKFlow::MCAST_NET) {
		$ref->{'multicast'}{'total'}{$which}{'flows'}++;
		$ref->{'multicast'}{'total'}{$which}{'bytes'} += $bytes;
		$ref->{'multicast'}{'total'}{$which}{'pkts'} += $pkts;
	}

EOF
	}

	if (defined $ref->{'protocol'}) {
	$countpackets.= <<'EOF';
	if (defined $ref->{'protocol'}{$protocol}) {
		$ref->{'protocol'}{$protocol}{'total'}{$which}{'flows'}++;
		$ref->{'protocol'}{$protocol}{'total'}{$which}{'bytes'} += $bytes;
		$ref->{'protocol'}{$protocol}{'total'}{$which}{'pkts'} += $pkts;
EOF
	}
	if (defined $ref->{'protocol'} && defined $ref->{'protocol'}{'other'}) {
	$countpackets.= <<'EOF';
	} else {
		$ref->{'protocol'}{'other'}{'total'}{$which}{'flows'}++;
		$ref->{'protocol'}{'other'}{'total'}{$which}{'bytes'} += $bytes;
		$ref->{'protocol'}{'other'}{'total'}{$which}{'pkts'} += $pkts;
EOF
	}
	if (defined $ref->{'protocol'}) {
	$countpackets.= <<'EOF';
	}
	
EOF
	}

	if (defined $ref->{'service'}) {
	$countpackets.= <<'EOF';
	if (defined $ref->{'service'}{$protocol}) {
		my $application;
		if (defined ($application=$ref->{'service'}{$protocol}{$dstport})) {
			$application->{'dst'}{$which}{'flows'}++;
			$application->{'dst'}{$which}{'bytes'} += $bytes;
			$application->{'dst'}{$which}{'pkts'} += $pkts;
			$servicecounted=1;
		} elsif (defined ($application=$ref->{'service'}{$protocol}{$srcport})) {
			$application->{'src'}{$which}{'flows'}++;
			$application->{'src'}{$which}{'bytes'} += $bytes;
			$application->{'src'}{$which}{'pkts'} += $pkts;
			$servicecounted=1;
EOF
	}
	if (defined $ref->{'service'} && defined $ref->{'ftp'}) {
		if  (!defined $ref->{'application'}{'other'}) {
		$countpackets.= <<'EOF';
		} else {
			countftp(\%{$ref->{'ftp'}},$which);
EOF
		} else {
		$countpackets.= <<'EOF';
		} elsif ( countftp(\%{$ref->{'ftp'}},$which) ) {
EOF
		}
	}
	if (defined $ref->{'service'} && defined $ref->{'application'}{'other'}) {
	$countpackets.= <<'EOF';
		} else {
			$ref->{'application'}{'other'}{'dst'}{$which}{'flows'}++;
			$ref->{'application'}{'other'}{'dst'}{$which}{'bytes'} += $bytes;
			$ref->{'application'}{'other'}{'dst'}{$which}{'pkts'} += $pkts;
			$servicecounted=1;
EOF
	}
	if (defined $ref->{'service'} && defined $ref->{'application'}{'other'} && defined $ref->{'scoreboardother'} && defined $ref->{'scoreboardother'}{hosts}) {
	$countpackets.= <<'EOF';
			$refref=$ref->{'scoreboardother'}{hosts};
			$refref->{'dst'}{'flows'}{$dstip}{$which} ++;
			$refref->{'dst'}{'bytes'}{$dstip}{$which} += $bytes;
			$refref->{'dst'}{'pkts'}{$dstip}{$which} += $pkts;
			$refref->{'src'}{'flows'}{$srcip}{$which} ++;
			$refref->{'src'}{'bytes'}{$srcip}{$which} += $bytes;
			$refref->{'src'}{'pkts'}{$srcip}{$which} += $pkts;

EOF
	}

	if (defined $ref->{'service'} && defined $ref->{'application'}{'other'} && defined $ref->{'scoreboardother'} && defined $ref->{'scoreboardother'}{ports}) {
	$countpackets.= <<'EOF';
			$refref=$ref->{'scoreboardother'}{ports};
			$refref->{'dst'}{'flows'}{$dstport}{$which} ++;
			$refref->{'dst'}{'bytes'}{$dstport}{$which} += $bytes;
			$refref->{'dst'}{'pkts'}{$dstport}{$which} += $pkts;
			$refref->{'src'}{'flows'}{$srcport}{$which} ++;
			$refref->{'src'}{'bytes'}{$srcport}{$which} += $bytes;
			$refref->{'src'}{'pkts'}{$srcport}{$which} += $pkts;
	
EOF
	}
	if (defined $ref->{'service'}) {
	$countpackets.= <<'EOF';
		}
	}
EOF
	}
	
	if (!defined $ref->{'service'} && defined $ref->{'ftp'}) {
	
	$countpackets.= <<'EOF';
	countftp(\%{$ref->{'ftp'}},$which);

EOF
	}

	if (defined $ref->{'scoreboard'} && defined $ref->{'scoreboard'}{hosts}) {
	$countpackets.= <<'EOF';
	$ref->{'scoreboard'}{hosts}{'dst'}{'flows'}{$dstip}{$which} ++;
	$ref->{'scoreboard'}{hosts}{'dst'}{'bytes'}{$dstip}{$which} += $bytes;
	$ref->{'scoreboard'}{hosts}{'dst'}{'pkts'}{$dstip}{$which} += $pkts;
	if (! defined $ref->{'scoreboard'}{hosts}{'dst'}{$dstip}{ipsrc} ) {
		$ref->{'scoreboard'}{hosts}{'dst'}{$dstip}{ipsrc}=$dstport;
	} elsif ($ref->{'scoreboard'}{hosts}{'dst'}{$dstip}{ipsrc}!=$dstport) {
		$ref->{'scoreboard'}{hosts}{'dst'}{$dstip}{ipsrc}="*";
	}
	$ref->{'scoreboard'}{hosts}{'src'}{'flows'}{$srcip}{$which} ++;
	$ref->{'scoreboard'}{hosts}{'src'}{'bytes'}{$srcip}{$which} += $bytes;
	$ref->{'scoreboard'}{hosts}{'src'}{'pkts'}{$srcip}{$which} += $pkts;
	if (! defined $ref->{'scoreboard'}{hosts}{'src'}{$srcip}{ipsrc} ) {
		$ref->{'scoreboard'}{hosts}{'src'}{$srcip}{ipsrc}=$srcport;
	} elsif ($ref->{'scoreboard'}{hosts}{'src'}{$srcip}{ipsrc}!=$srcport) {
		$ref->{'scoreboard'}{hosts}{'src'}{$srcip}{ipsrc}="*";
	}

EOF
	}

	if (defined $ref->{'scoreboard'} && defined $ref->{'scoreboard'}{ports}) {
	$countpackets.= <<'EOF';
	$ref->{'scoreboard'}{ports}{'dst'}{'flows'}{$dstport}{$which} ++;
	$ref->{'scoreboard'}{ports}{'dst'}{'bytes'}{$dstport}{$which} += $bytes;
	$ref->{'scoreboard'}{ports}{'dst'}{'pkts'}{$dstport}{$which} += $pkts;
	if (! defined $ref->{'scoreboard'}{ports}{'dst'}{$dstport}{ipsrc} ) {
		$ref->{'scoreboard'}{ports}{'dst'}{$dstport}{ipsrc}=$dstip;
	} elsif ($ref->{'scoreboard'}{ports}{'dst'}{$dstport}{ipsrc}!=$dstip) {
		$ref->{'scoreboard'}{ports}{'dst'}{$dstport}{ipsrc}="*";
	}
	$ref->{'scoreboard'}{ports}{'src'}{'flows'}{$srcport}{$which} ++;
	$ref->{'scoreboard'}{ports}{'src'}{'bytes'}{$srcport}{$which} += $bytes;
	$ref->{'scoreboard'}{ports}{'src'}{'pkts'}{$srcport}{$which} += $pkts;
	if (! defined $ref->{'scoreboard'}{ports}{'src'}{$srcport}{ipsrc} ) {
		$ref->{'scoreboard'}{ports}{'src'}{$srcport}{ipsrc}=$srcip;
	} elsif ($ref->{'scoreboard'}{ports}{'src'}{$srcport}{ipsrc}!=$srcip) {
		$ref->{'scoreboard'}{ports}{'src'}{$srcport}{ipsrc}="*";
	}

EOF
	}

	if ($ref->{'monitor'} eq "yes") {
	$countpackets.= <<'EOF';
	print "SRC=".inet_ntoa(pack(N,$srcaddr)).", SPORT=".$srcport.", DST=".inet_ntoa(pack(N,$dstaddr)).", DPORT=".$dstport.", EXP=".inet_ntoa(pack(N,$exporter))."\n";

EOF
	}
	$countpackets.= "}";
	$ref->{countpackets}=eval $countpackets;
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
				$servicecounted=1;
				#if (($srcport == 20) || ($dstport == 20)) {
				#	print "Active FTP session $which: $srcaddr -> $dstaddr $bytes bytes\n";
				#} else {
				#	print "Passive FTP session $which: $srcaddr -> $dstaddr $bytes bytes\n";
				#}	
				$ref->{cache}{"$dstaddr:$srcaddr"} = $endtime;
				return 1;
			} elsif ( defined $ref->{cache}{"$srcaddr:$dstaddr"} ) {
				$ref->{'src'}{$which}{'flows'}++;
				$ref->{'src'}{$which}{'bytes'} += $bytes;
				$ref->{'src'}{$which}{'pkts'} += $pkts;
				$servicecounted=1;
				#if (($srcport == 20) || ($dstport == 20)) {
				#	print "Active FTP session $which: $srcaddr -> $dstaddr $bytes bytes\n";
				#} else {
				#	print "Passive FTP session $which: $srcaddr -> $dstaddr $bytes bytes\n";
				#}	
				$ref->{cache}{"$srcaddr:$dstaddr"} = $endtime;
				return 1;
			} 
		} elsif ($dstport == 21) {
			$ref->{'dst'}{$which}{'flows'}++;
			$ref->{'dst'}{$which}{'bytes'} += $bytes;
			$ref->{'dst'}{$which}{'pkts'} += $pkts;
			$servicecounted=1;
			if (!defined $ref->{cache}{"$dstaddr:$srcaddr"}) {
				$ref->{cache}{"$dstaddr:$srcaddr"}=$endtime;
			}
			return 1;
		} elsif ($srcport == 21) {
			$ref->{'src'}{$which}{'flows'}++;
			$ref->{'src'}{$which}{'bytes'} += $bytes;
			$ref->{'src'}{$which}{'pkts'} += $pkts;
			$servicecounted=1;
			if (!defined $ref->{cache}{"$srcaddr:$dstaddr"}) {
				$ref->{cache}{"$srcaddr:$dstaddr"}=$endtime;
			}
			return 1;
		} else {
			return 0;
		}	
	}
}

sub perfile {
    # Only do this, so we get the filetime from our super-class
    my $self = shift;

    $JKFlow::totals = ();	# Clear this out

    $self->SUPER::perfile(@_);
}

sub reporttorrd {

	use RRDs;			# To actually produce results
	my $self=shift;
	my $dir=shift;
	my $name=shift;
	my $ref=shift;
	my $samplerate=shift;
	my $tmp;
	my @values = ();
	my $file=$JKFlow::RRDDIR."/".$dir."/".$name;

	# First, always generate a totals report
	# createGeneralRRD we get from our parent, FlowScan
	# Create a new rrd if one doesn't exist
	if (! -f $file) {
		print "Creating RRD-File ".$file."\n";
		$self->createGeneralRRD($file,
			    qw(
			       ABSOLUTE in_bytes
			       ABSOLUTE out_bytes
			       ABSOLUTE in_pkts
			       ABSOLUTE out_pkts
			       ABSOLUTE in_flows
			       ABSOLUTE out_flows
			       ));
	}

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
	$self->updateRRD($dir,$name, @values);
	#print "File: $dir $name @values\n";
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
		reporttorrd($self,$dir,"total.rrd",\%{$ref->{'total'}},$samplerate);
	}

	if (defined $ref->{'tos'}) {	
		foreach my $tos ('normal','other') {
			reporttorrd($self,$dir,"tos_". $tos . ".rrd",\%{$ref->{'tos'}{$tos}},$samplerate);
 		}
	}

	if (defined $ref->{'multicast'}) {	
		reporttorrd($self,$dir,"protocol_multicast.rrd",\%{$ref->{'multicast'}{'total'}},$samplerate);
	}

	if (defined $ref->{'protocol'}) {	
		foreach my $protocol (keys %{$ref->{'protocol'}}) {
			if (!($tmp = getprotobynumber($protocol))) {
				$tmp = $protocol;
			}
			if ($protocol eq 'other') {
				$tmp = 'other';
			}
			reporttorrd($self,$dir,"protocol_" . $tmp . ".rrd",\%{$ref->{'protocol'}{$protocol}{'total'}},$samplerate);
		}
	}

	if (defined $ref->{'application'}) {	
		foreach my $src ('src','dst') {
			foreach my $application (keys %{$ref->{'application'}}) {
				reporttorrd($self,$dir,"service_" . $application . "_" . $src . ".rrd",\%{$ref->{'application'}{$application}{$src}},$samplerate);
			}
		}
	}

	if (defined $ref->{'ftp'}) {	
		foreach my $src ('src','dst') {
			reporttorrd($self,$dir,"service_ftp_" . $src . ".rrd",\%{$ref->{'ftp'}{$src}},$samplerate);
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
		scoreboard($self, $dir , \%{$ref->{'scoreboard'}}, $samplerate );
	}
	if (defined $ref->{'scoreboardother'}) {
		scoreboard($self, $dir . "/other" , \%{$ref->{'scoreboardother'}}, $samplerate );
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

	if (defined $JKFlow::mylist{'all'}) {
		if (! -d $JKFlow::RRDDIR."/all" ) {
			mkdir($JKFlow::RRDDIR."/all",0755);
		}
		if (! -d $JKFlow::SCOREDIR."/all" ) {
			mkdir($JKFlow::SCOREDIR."/all",0755);
		}
		if (! -d $JKFlow::SCOREDIR."/all/other" ) {
			mkdir($JKFlow::SCOREDIR."/all/other",0755);
		}
		reporttorrdfiles($self, "/all",\%{$JKFlow::mylist{'all'}},$JKFlow::mylist{'all'}{'samplerate'});
	}

	foreach my $direction (keys %{$JKFlow::mylist{'direction'}}) {
		if (! -d $JKFlow::RRDDIR."/".$direction ) {
			mkdir($JKFlow::RRDDIR."/".$direction ,0755);
		}
		if (! -d $JKFlow::SCOREDIR."/".$direction ) {
			mkdir($JKFlow::SCOREDIR."/".$direction ,0755);
		}
		if (! -d $JKFlow::SCOREDIR."/".$direction . "/other" ) {
			mkdir($JKFlow::SCOREDIR."/".$direction . "/other" ,0755);
		}
		reporttorrdfiles($self, "/" . $direction, \%{$JKFlow::mylist{'direction'}{$direction}},$JKFlow::mylist{'direction'}{$direction}{'samplerate'});
	}   
}

# Lifted totally and shamelessly from CampusIO.pm
# I think perhaps this goes into FlowScan.pm, but...
sub updateRRD {
   my $self = shift;
   my $dir = shift;
   my $file = shift;
   my @values = @_;

   RRDs::update($JKFlow::RRDDIR."/".$dir."/".$file, $self->{filetime} . ':' . join(':', @values));
   my $err=RRDs::error;
   warn "ERROR updating". $JKFlow::RRDDIR."/".$dir."/"."$file: $err\n" if ($err);
}


# Handle writing our HTML scoreboard reports
sub scoreboard {    
	my $self = shift;
	my $dir = shift;
	my $ref = shift;
	my $samplerate = shift;

	my($i,$file,$item,$hr);
	my (@values, @sorted);
	my(%dnscache) = ();
	my(%newaggdata) = ();
	my($table,$row);

	
	# Next, open the file, making any necessary directories
	($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
		localtime($self->{filetime});  

	$mon++; $year += 1900;

	foreach my $type ('hosts','ports') { 

		next if (!defined $ref->{aggregate}{$type}{report} && !defined $ref->{$type});
		
		if (defined $ref->{$type}{all}) {

			$file=$JKFlow::SCOREDIR.$dir."/".$type;
			
			if (! -d $file) {
				mkdir($file,0755) || die "Cannot mkdir $file ($!)\n";
			}

			$file=sprintf("%s%s/%s/%4.4d-%2.2d-%2.2d",$JKFlow::SCOREDIR,$dir,$type,$year,$mon,$mday);

			if (! -d $file) {
				mkdir($file,0755) || die "Cannot mkdir $file ($!)\n";
			}

			#$file = sprintf("%s/%2.2d",$file,$hour);
			#if (! -d $file) {
			#	mkdir($file,0755) || die "Cannot mkdir $file ($!)\n";
			#}

			$file = sprintf("%s/%2.2d:%2.2d:%2.2d.html",$file,$hour,$min,$sec);
			open(HTML,">$file") || die "Could not write to $file ($!)\n";

			# Now, print out our header stuff into the file
			print HTML "<html>\n<body bgcolor=\"\#ffffff\">\n<center>\n\n";

		}
		
		# Now, print out our 6 topN tables
		my %columns = ('bytes' => 3, 'pkts' => 5, 'flows' => 7);

		foreach my $srcdst ('src','dst') {
			@values = ();

			foreach my $key ('bytes','pkts','flows') {

				foreach my $direction ('in', 'out') {

					@sorted = sort {$ref->{$type}{$srcdst}{$key}{$b}{$direction} <=> $ref->{$type}{$srcdst}{$key}{$a}{$direction}} (keys %{$ref->{$type}{$srcdst}{$key}});
	    
					$table = new HTML::Table;
					
					if (defined $ref->{$type}{all}) {
					
						# This part lifted totally from CampusIO.pm. Thanks, dave!
						
						die unless ref($table);
						$table->setBorder(1);
						$table->setCellSpacing(0);
						$table->setCellPadding(3);
	
						$table->setCaption("Top $JKFlow::scorekeep by " .
							"<b>$key $srcdst $direction</b><br>\n" .
							"for flow sample ending " .
							scalar(localtime($self->{filetime})),
							'TOP');

						$row = 1;
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
						
					}

					# Get the in and out hr's for ease of use
					my ($in, $out);
	
					for($i=0;$i < @sorted; $i++) {
						last unless $i < $JKFlow::SCOREKEEP;
						$item = $sorted[$i];
	
						if (!(defined($newaggdata{$type}{$item}))) { # Add this to aggdata 1x
							$newaggdata{$type}{$item} = {
								'bytesin'  => $ref->{$type}{$srcdst}{bytes}{$item}{in} * $samplerate,
								'bytesout' => $ref->{$type}{$srcdst}{bytes}{$item}{out} * $samplerate,
								'pktsin'   => $ref->{$type}{$srcdst}{pkts}{$item}{in} * $samplerate,
								'pktsout'  => $ref->{$type}{$srcdst}{pkts}{$item}{out} * $samplerate,
								'flowsin'  => $ref->{$type}{$srcdst}{flows}{$item}{in} * $samplerate,
								'flowsout' => $ref->{$type}{$srcdst}{flows}{$item}{out} * $samplerate,
								'ipsrc' => $ref->{$type}{$srcdst}{$item}{ipsrc}
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

						if (defined $ref->{$type}{all}) {
						
							$table->addRow( sprintf("#%d",$i+1),
							#$dnscache{$ip},      # IP Name/Address
							$item,						

							# Bits/sec in
							scale("%.1f", ($ref->{$type}{$srcdst}{bytes}{$item}{in}*8)/$JKFlow::SAMPLETIME),

							# Bits/sec out
							scale("%.1f", ($ref->{$type}{$srcdst}{bytes}{$item}{out}*8)/$JKFlow::SAMPLETIME),
					
							# Pkts/sec in
							scale("%.1f", ($ref->{$type}{$srcdst}{pkts}{$item}{in}/$JKFlow::SAMPLETIME)),

							# Pkts/sec out
							scale("%.1f", ($ref->{$type}{$srcdst}{pkts}{$item}{out}/$JKFlow::SAMPLETIME)),

							# Flows/sec in
							scale("%.1f", ($ref->{$type}{$srcdst}{flows}{$item}{in}/$JKFlow::SAMPLETIME)),

							# Flows/sec out
							scale("%.1f", ($ref->{$type}{$srcdst}{flows}{$item}{out}/$JKFlow::SAMPLETIME)) );

							$table->setRowAlign($row, 'RIGHT');
							$table->setCellBGColor($row, $columns{$key} + ('out' eq $direction), '#add8e6'); # light blue
							$row++;
						}
					}
				if (defined $ref->{$type}{all}) { print HTML "<p>\n$table</p>\n\n"; }
				}
			}
		}
		
		if (defined $ref->{$type}{all}) {
		
			# Print footers
			print HTML "\n</center>\n</body>\n</html>\n";

			# Close the file, and make $scorepage point at this page
			close HTML;

		}

		# Update links
		if (defined $ref->{latest}{$type}) {
			if ($ref->{latest}{$type} !~ /^\/.*/) {
				unlink $JKFlow::SCOREDIR.$dir."/".$ref->{latest}{$type} ||
					warn "Could not remove ".$JKFlow::SCOREDIR.$dir.$ref->{latest}{$type}." ($!)\n";
				symlink $file, $JKFlow::SCOREDIR.$dir."/".$ref->{latest}{$type} ||
					warn "Could not create symlink to $JKFlow::SCOREDIR.$dir.$ref->{latest}{$type} ($!)\n";
			} else {
				unlink $ref->{latest}{$type} ||
					warn "Could not remove ".$ref->{latest}{$type}." ($!)\n";
				symlink $file, $ref->{latest}{$type} ||
					warn "Could not create symlink to ".$ref->{latest}{$type}." ($!)\n";
			}
		}
	
		##### AGGDATA ######
		&countAggdata($dir,$ref->{aggregate}{$type}{report},\%{$newaggdata{$type}},$self->{filetime});
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

sub countAggdata($) {

	my $dir=shift;
	my $ref=shift;
	my $newaggdata=shift;
	my $filetime=shift;

	foreach my $report (@{$ref}) {
		if ($filetime > $report->{startperiod} + $report->{count} * $JKFlow::SAMPLETIME ) {
			# Write the aggregate table
			# Next, open the file, making any necessary directories
			if (($report->{startperiod} == 0) || !(defined $report->{startperiod})) {
				$report->{startperiod}=$filetime;
			} else {
				my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($report->{startperiod});  
				$file=sprintf("%s-%4.4d-%2.2d-%2.2d-%2.2d:%2.2d:%2.2d.html",$report->{filenamebase},$year+1900,$mon+1,$mday,$hour,$min,$sec);
				#print "Wrote Agg Score:". $JKFlow::SCOREDIR.$dir.$file ."\n";
				if ($file !~ /^\/.*/) {
					&writeAggScoreboard($report->{aggdata}, $report->{scorekeep}, $report->{counter}, $JKFlow::SCOREDIR.$dir."/".$file);
				} else {
					&writeAggScoreboard($report->{aggdata}, $report->{scorekeep}, $report->{counter}, $file);
				}
				$report->{counter}=0;
				$report->{startperiod} = $filetime - ($filetime % ($report->{count} * $JKFlow::SAMPLETIME));
				delete $report->{aggdata};
			}
		}
		# Merge newaggdata and aggdata
		foreach my $porthost (keys %{$newaggdata}) {
			$report->{aggdata}{$porthost}{'count'}++;
			$report->{aggdata}{$porthost}{'bytesin'}  += $newaggdata->{$porthost}{'bytesin'};
			$report->{aggdata}{$porthost}{'bytesout'} += $newaggdata->{$porthost}{'bytesout'};
			$report->{aggdata}{$porthost}{'pktsin'}   += $newaggdata->{$porthost}{'pktsin'};
			$report->{aggdata}{$porthost}{'pktsout'}  += $newaggdata->{$porthost}{'pktsout'};
			$report->{aggdata}{$porthost}{'flowsin'}  += $newaggdata->{$porthost}{'flowsin'};
			$report->{aggdata}{$porthost}{'flowsout'} += $newaggdata->{$porthost}{'flowsout'};
			if (!defined $report->{aggdata}{$porthost}{'ipsrc'}) {
				$report->{aggdata}{$porthost}{'ipsrc'}=$newaggdata->{$porthost}{'ipsrc'};
			} elsif ($report->{aggdata}{$porthost}{'ipsrc'}!=$newaggdata->{$porthost}{'ipsrc'}) {
				$report->{aggdata}{$porthost}{'ipsrc'}='*';
			}
			#print "IPSRC".$report->{aggdata}{$porthost}{'ipsrc'}."\n";
		}
		# Increment counter
		$report->{aggdata}{'numresults'}++;
		if ($report->{aggdata}{'numresults'} > $report->{numkeep}) {
			# Prune this shit
			$report->{aggdata}{'numresults'} >>= 1;
			foreach $porthost (keys %{$report->{aggdata}}) {
				next if ($porthost =~ /numresults/);           # Skip this, not a ref
				if ($report->{aggdata}{$porthost}{'count'} == 1) {     # Delete singletons
					delete $report->{aggdata}{$porthost};
				} else {
					$report->{aggdata}{$porthost}{'count'}    >>= 1;   # Divide by 2
					$report->{aggdata}{$porthost}{'bytesin'}  >>= 1;
					$report->{aggdata}{$porthost}{'bytesout'} >>= 1;
					$report->{aggdata}{$porthost}{'pktsin'}   >>= 1;
					$report->{aggdata}{$porthost}{'pktsout'}  >>= 1;
					$report->{aggdata}{$porthost}{'flowsin'}  >>= 1;
					$report->{aggdata}{$porthost}{'flowsout'} >>= 1;
				}
			}
		}
		$report->{counter} ++;
	}
}

# Function to print the pretty table of over-all winners
sub writeAggScoreboard ()
{
    my %data = %{(shift)};
    my $scorekeep = shift;
    my $count = shift;
    my $file = shift;
    my($key, $i);
    my(@sorted);
    my(%dnscache);
    my($tmp) = $data{'numresults'};

    delete $data{'numresults'};

    open(OUT,">$file") ||
	die "Cannot open $file for write ($!)\n";

    print OUT "<html>\n<body bgcolor=\"\#ffffff\">\n\n<center>\n";
    print OUT "<h3> Average rankings for the last ".$count." topN reports\n<hr>\n";
    print OUT "</center>\n";

    # Now, print out our 6 topN tables
    my %columns = ('bytes' => 4, 'pkts' => 6, 'flows' => 8);

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
	    
	    $table->setCaption("Top ".$scorekeep." by " .
			       "<b>$key $dir</b><br>\n" .
			       "built on aggregated topN " .
			       "average samples to date",
			       'TOP');

	    my $row = 1;
	    $table->addRow('<b>rank</b>',
			   "<b>address</b>",
			   "<b>address</b>",
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
		last unless $i < $scorekeep;
		my $ip = $sorted[$i];

#		if (!(defined($dnscache{$ip}))) { # No name here?
#		    if ($dnscache{$ip} = gethostbyaddr(pack("C4", 
#							split(/\./, $ip)),
#						       AF_INET)) {
#			$dnscache{$ip} . = "<br>$ip (" .
#			    $data{$ip}->{'count'} . " samples)";
#		    } else {
#			$dnscache{$ip} = $ip . " (" .
#			    $data{$ip}->{'count'} . " samples)";
#		    }
#		}

		my $div = $JKFlow::SAMPLETIME * $data{$ip}->{'count'};
		$table->addRow( sprintf("#%d",$i+1),
				# $dnscache{$ip},      
				$ip,			# Host / Port address
				
				$data{$ip}->{'ipsrc'},	# Port / Host address 
				
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