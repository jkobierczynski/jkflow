#! /usr/bin/perl -w

# CUGrapher.pl
# $Revision$
# Author: Matt Selsky <selsky@columbia.edu>
# Contact for help: <cuflow-users@columbia.edu>

use strict;
use CGI::Pretty qw(-nosticky :standard);
use RRDs;
use Digest::MD5 qw(md5_hex);
use Data::Dumper;

### Local settings ###

# directory with rrd files
my $rrddir = "/var/flows/reports/rrds";
# default number of hours to go back
my $hours = 48;
# duration of graph, starting from $hours ago
my $duration;
# organization name
my $organization = "Estimated Columbia University Campus";
# default graph width
my $width = 640;
# default graph height
my $height = 320;
# default image type (png/gif)
my $imageType = 'png';

### End local settings ###

# auto-flush STDOUT
$| = 1;

# report -> proper name
my %reportName = ( 'bits' => 'bits',
		   'pkts' => 'packets',
		   'flows' => 'flows' );

unless( param() ) {
    &showMenu();
}

# protocol/service -> filename
my %filename;
# lists of networks/protocols/services/routers
my (%network, %protocol, %service, %tos, %subdir);
#my (%network, %protocol, %service, %tos, %subdir @router, @subnet);
# should we show totals also?
my %total;
# hash for colors/CDEFs
my (%color, %cdef);
# are we in debug mode?
my $debug;

&getSubdir();
&getFilenames();
#&getNetworks();
&getImageType();
&setColors();
&getHours();
&getDuration();
&getWidth();
&getHeight();
&getDebug();

&doReport();

################################################################

# Image generation and display

sub generateImage {
    my @args = @_;
    my ($err1, $err2);

    unless( $debug ) {
	print header( -type => "image/${imageType}", -expires => 'now' );
        RRDs::graph( '-', @args);
	$err1 = RRDs::error;
	if( $err1 ) { # log & attempt to create image w/ error message in it
	    warn $err1, "\n";
	    RRDs::graph( '-', "--width=".$width,
		       "COMMENT:graph failed ($err1)\\n");
	    $err2 = RRDs::error;
	    if( $err2 ) { # log to stderr since we are totally broken
		warn "graph failed ($err1) and warning failed ($err2)\n";
	    }
	}
    }
    else {
	print header, '<pre>', join(" \\\n", @args), "\n"; exit;
    }
}

sub showMenu {
    my $q = new CGI::Pretty;
    my @list;

    print $q->header, $q->start_html( -title => 'Generate FlowScan graphs on the fly',
				      -bgcolor => 'ffffff' );
    
    print $q->start_form( -action => $q->self_url, -method => 'get' );

    print $q->start_table( { -align => 'center',
			     -cellspacing => '10' } );

    print $q->start_Tr( { -align => 'center',
			  -valign => 'top' } );

    print $q->td( { -rowspan => '2' },
		  "Report: ",
		  $q->popup_menu( -name => 'report',
				  -values => [sort keys %reportName],
				  -default => '' ) );
    
    my %hours = ( 6 => '6 hours',
    		  12 => '12 hours',
    		  24 => '1 day',
		  36 => '1,5 days',
		  48 => '2 days',
		  72 => '3 days',
		  96 => '4 days',
		  120 => '5 days',
		  168 => '1 week',
		  336 => '2 weeks',
		  504 => '3 weeks',
		  720 => '1 month' );

    print $q->td( { -align => 'right' },
		  "Time period: ",
		  $q->popup_menu( -name => 'hours',
				  -values => [sort {$a <=> $b} keys %hours],
				  -default => $hours,
				  -labels => \%hours ) );
    
    print $q->td( { -rowspan => '2' },
		  "Image type: ",
		  $q->popup_menu( -name => 'imageType',
				  -values => ['png', 'gif'],
				  -default => 'png' ) );
    
    print $q->td( { -rowspan => '2' },
		  "Width:",
		  $q->textfield( -name => "width",
				 -default => $width,
				 -size => 7 ) );
    
    print $q->td( { -rowspan => '2' },
		  "Height:",
		  $q->textfield( -name => "height",
				 -default => $height,
				 -size => 7 ) );

    print $q->end_Tr();

    print $q->start_Tr( { -align => 'center' } );

    print $q->td( { -align => 'right' },
		  "Duration: ",
		  $q->popup_menu( -name => 'duration',
				  -values => ['', sort {$a <=> $b} keys %hours],
				  -labels => \%hours ) );

    print $q->end_Tr();

    print $q->end_table();
    
    print $q->center( $q->submit( -name => '',
				  -value => 'Generate graph' ) );

    print $q->start_table( { align => 'center',
			     -border => '1' } );

    print $q->Tr( { -align => 'center' },
		  $q->td( i('Global') ),
		  $q->td( i('Protocol') ), $q->td( i('All Protos') ),
		  $q->td( i('Service') ), $q->td( i('All Svcs') ),
		  $q->td( i('TOS') ), $q->td( i('All TOS') ),
		  $q->td( i('Network') ),
		  $q->td( i('Total') ) );    

    print $q->start_Tr;

    print $q->td( { -align => 'center' }, "All",
		      $q->hidden( -name => 'router', -default => "all" ) );

    print $q->td( $q->scrolling_list( -name => "all_protocol",
				      -values => [sort &getProtocolList("")],
				      -size => 5,
				      -multiple => 'true' ) );

    print $q->td( $q->checkbox( -name => "all_all_protocols",
				-value => '1',
				-label => 'Yes' ) );
	
    print $q->td( $q->scrolling_list( -name => "all_service",
				      -values => [sort &getServiceList("")],
				      -size => 5,
				      -multiple => 'true' ) );

    print $q->td( $q->checkbox( -name => "all_all_services",
				-value => '1',
				-label => 'Yes' ) );

    print $q->td( $q->scrolling_list( -name => "all_tos",
				      -values => [sort &getTosList("")],
			              -size => 5,
				      -multiple => 'true' ) );

    print $q->td( $q->checkbox( -name => "all_all_tos",
				-value => '1',
				-label => 'Yes' ) );

    print $q->td( $q->scrolling_list( -name => "all_network",
				      -values => [sort &getNetworkList()],
				      -size => 5,
			              -multiple => 'true' ) );
	
    print $q->td( $q->checkbox( -name => "all_total",
				    -value => '1',
				    -label => 'Yes') );
	
    print $q->end_Tr;

    foreach my $type ( 'router', 'total_router', 'subnet', 'total_subnet' ) {

      print $q->Tr( { -align => 'center' },
		  $q->td( i("$type") ),
		  $q->td( i('Protocol') ), $q->td( i('All Protos') ),
		  $q->td( i('Service') ), $q->td( i('All Svcs') ),
		  $q->td( i('TOS') ), $q->td( i('All TOS') ),
		  $q->td( i('Network') ),
		  $q->td( i('Total') ) );    

      if ($type eq 'router') { @list = getRouterList(); } 
      if ($type eq 'total_router') { @list = ( 'total_router' ); } 
      if ($type eq 'subnet') { @list = getSubnetList(); } 
      if ($type eq 'total_subnet') { @list = ( 'total_subnet' ); } 
      foreach my $r (  sort @list ) {

	print $q->start_Tr;
	print $q->td( { -align => 'center' }, $q->b($r),
		      $q->hidden( -name => $type, -default => $r ) );
        if ($type eq 'router' || $type eq 'subnet') {
		print $q->td( $q->scrolling_list( -name => "${r}_protocol",
					  -values => [sort &getProtocolList($type."_".$r)],
					  -size => 5,
					  -multiple => 'true' ) );
		print $q->td( $q->checkbox( -name => "${r}_all_protocols",
					    -value => '1',
					    -label => 'Yes' ) );
		print $q->td( $q->scrolling_list( -name => "${r}_service",
					  -values => [sort &getServiceList($type."_".$r)],
					  -size => 5,
					  -multiple => 'true' ) );
		print $q->td( $q->checkbox( -name => "${r}_all_services",
						-value => '1',
				  		-label => 'Yes' ) );
	} else {
		print $q->td( $q->scrolling_list( -name => "${r}_protocol",
					  -values => [ 'multicast' ],
					  -size => 1,
					  -multiple => 'true' ) );
		print $q->td( $q->checkbox( -name => "${r}_all_protocols",
					    -value => '1',
					    -label => 'Yes' ) );
	        print $q->td( '&nbsp;' );
	        print $q->td( '&nbsp;' );
	}
        if ($type eq 'total_router' || $type eq 'total_subnet') {
		print $q->td( $q->scrolling_list( -name => "${r}_tos",
						  -values => [sort &getTosList($type)],
						  -size => 5,
						  -multiple => 'true' ) );
	} else {
		print $q->td( $q->scrolling_list( -name => "${r}_tos",
						  -values => [sort &getTosList($type."_".$r)],
						  -size => 5,
						  -multiple => 'true' ) );
        }
	print $q->td( $q->checkbox( -name => "${r}_all_tos",
				    -value => '1',
				    -label => 'Yes' ) );
        print $q->td( '&nbsp;' );
	print $q->td( $q->checkbox( -name => "${r}_total",
				    -value => '1',
				    -label => 'Yes') );
	print $q->end_Tr;

      }
    }

    print $q->end_table();
    
    print $q->br;

    print $q->center( $q->submit( -name => '',
				  -value => 'Generate graph' ) );

    print $q->end_form;

    print $q->end_html;    
    exit;
}

sub browserDie {
    print header;
    print start_html(-title => 'Error Occurred',
		     -bgcolor => 'ffffff');
    print '<pre>', "\n";
    print @_;
    print "\n", '</pre>', "\n";
    exit;
}

## Parse param()

sub getImageType {
    if( param('imageType') ) {
	if( param('imageType') eq 'png' || param('imageType') eq 'gif' ) {
	    $imageType = param('imageType');
	} else { &browserDie('Invalid imageType parameter') }
    }
}

### New getSubdir

sub getSubdir {
    foreach my $r ( getRouterList() ) {
      if (  	param($r.'_protocol') || param($r.'_all_protocols') ||
		param($r.'_service') || param($r.'_all_services') ||
		param($r.'_tos') || param($r.'_all_tos') ||
		param($r.'_total') ) {
        if( $r eq 'total_router') {
           if ( -d $rrddir.'/total_router' ) {
              $subdir{'total_subnet'}{'dir'} = '/total_router';
           }
           else {
           &browserDie('Total router directory not found:'.$rrddir.'/total_router');
           }
        }
        else {
           if ( -d $rrddir.'/router_'.$r ) {
              $subdir{'router'}{$r}{'dir'} = '/'.$r;
           }
           else {
           &browserDie('Subnet directory not found:'.$rrddir.'/'.$r);
           }
        }
      }
    }
    foreach my $s ( getSubnetList() ) {
      if (  	param($s.'_protocol') || param($s.'_all_protocols') ||
		param($s.'_service') || param($s.'_all_services') ||
		param($s.'_tos') || param($s.'_all_tos') ||
		param($s.'_total') ) {
        if( $s eq 'total_subnet') {
           if ( -d $rrddir.'/total_subnet' ) {
              $subdir{'total_subnet'}{'dir'} = '/total_subnet';
           }
           else {
           &browserDie('Total subnet directory not found:'.$rrddir.'/total_subnet');
           }
        }
        else {
           if ( -d $rrddir.'/subnet_'.$s ) {
              $subdir{'subnet'}{$s}{'dir'} = '/'.$s;
           }
           else {
           &browserDie('Subnet directory not found:'.$rrddir.'/'.$s);
           }
        }
      }
    }
}
# Generate list of protocols and resolve filenames
sub getFilenames {
    foreach my $type ('router','subnet') {
        foreach my $r (keys %{$subdir{$type}}) {
            foreach my $p (param("${r}_protocol")) { 
                $subdir{$type}{$r}{'protocol'}{$p}="${rrddir}/${type}_${r}/protocol_${p}.rrd";
                -f $subdir{$type}{$r}{'protocol'}{$p} or &browserDie("Cannot find file $subdir{$type}{$r}{'protocol'}{$p}");
            }
            if ( param("${r}_all_protocols")) {
                foreach my $p (getProtocolList($type."_".$r)) {
                $subdir{$type}{$r}{'protocol'}{$p}="${rrddir}/${type}_${r}/protocol_${p}.rrd";
                -f $subdir{$type}{$r}{'protocol'}{$p} or &browserDie("Cannot find file $subdir{$type}{$r}{'protocol'}{$p}");
                }
            }
            foreach my $s (param("${r}_service")) { 
                $subdir{$type}{$r}{'service'}{$s}="${rrddir}/${type}_${r}/service_${s}";
                -f $subdir{$type}{$r}{'service'}{$s}.'_src.rrd' or &browserDie("Cannot find file $subdir{$type}{$r}{'service'}{$s}");
                -f $subdir{$type}{$r}{'service'}{$s}.'_dst.rrd' or &browserDie("Cannot find file $subdir{$type}{$r}{'service'}{$s}");
            }
            if ( param("${r}_all_services")) {
                foreach my $s (getServiceList($type."_".$r)) {
                $subdir{$type}{$r}{'service'}{$s}="${rrddir}/${type}_${r}/service_${s}";
                -f $subdir{$type}{$r}{'service'}{$s}.'_src.rrd' or &browserDie("Cannot find file $subdir{$type}{$r}{'service'}{$s}");
                -f $subdir{$type}{$r}{'service'}{$s}.'_dst.rrd' or &browserDie("Cannot find file $subdir{$type}{$r}{'service'}{$s}");
                }
            }
  	    if ( param("${r}_tos_all")) {
            	foreach my $t (param("${r}_tos")) { 
           	   $subdir{$type}{$r}{'tos'}{$t}="${rrddir}/${type}_${r}/tos_${t}.rrd";
              	  -f $subdir{$type}{$r}{'tos'}{$t} or &browserDie("Cannot find file $subdir{$type}{$r}{'tos'}{$t}");
            	}
	    }
            if ( param("${r}_all_tos")) {
                foreach my $s (getTosList($type."_".$r)) {
                $subdir{$type}{$r}{'tos'}{$s}="${rrddir}/${type}_${r}/tos_${s}.rrd";
                -f $subdir{$type}{$r}{'tos'}{$s} or &browserDie("Cannot find file $subdir{$type}{$r}{'tos'}{$s}");
                -f $subdir{$type}{$r}{'tos'}{$s} or &browserDie("Cannot find file $subdir{$type}{$r}{'tos'}{$s}");
                }
            }
             #Dit moet altijd gebeuren voor de percentages if ( param("${r}_total")) {
	            $subdir{$type}{$r}{'total'}="${rrddir}/${type}_${r}/total.rrd";
 	           -f $subdir{$type}{$r}{'total'} or &browserDie("Cannot find file $subdir{$type}{$r}{'total'}");
            #}
        }
    }
    foreach my $r ('total_router','total_subnet') {
	if ( param("${r}_all_tos")) {
	        foreach my $t (getTosList($r)) {
 			$subdir{$r}{'tos'}{$t}="${rrddir}/${r}/tos_${t}.rrd";
			-f $subdir{$r}{'tos'}{$t} or &browserDie("Cannot find file $subdir{$r}{'tos'}{$t}");
	        }
	}
        foreach my $t (getTosList($r)) {
		if ( param("${r}_tos_${t}")) {
	 		$subdir{$r}{'tos'}{$t}="${rrddir}/${r}/tos_${t}.rrd";
			-f $subdir{$r}{'tos'}{$t} or &browserDie("Cannot find file $subdir{$r}{'tos'}{$t}");
			}
  		}
        if ( param("${r}_protocol_multicast") || param("${r}_all_protocols")) {
		$subdir{$r}{'protocol'}{'multicast'}="${rrddir}/${r}/protocol_multicast.rrd";
		-f $subdir{$r}{'protocol'}{'multicast'} or &browserDie("Cannot find file $subdir{$r}{'protocol'}{'multicast'}");
	}
        if ( param("${r}_total") || param("${r}_tos") || param("${r}_all_tos") || param("${r}_protocol_multicast") || param("${r}_all_protocols") ) {
		$subdir{$r}{'total'}="${rrddir}/${r}/total.rrd";
		-f $subdir{$r}{'total'} or &browserDie("Cannot find file $subdir{$r}{'total'}");
	}
    }
#    foreach my $p (param("all_all_protocols")) {
#	$subdir{'all'}{'protocol'}="${rrddir}/protocol_${p}.rrd";
#	-f $subdir{'all'}{'protocol'}{$p} or &browserDie("Cannot find file $subdir{'all'}{'protocol'}{$p}");
#    }
    foreach my $p (getProtocolList('')) { 
        if ( param("all_protocol")) {
        $subdir{'all'}{'protocol'}{$p}="${rrddir}/protocol_${p}.rrd";
        -f $subdir{'all'}{'protocol'}{$p} or &browserDie("Cannot find file $subdir{'all'}{'protocol'}{$p}");
        }
    }
    if (param("all_all_protocols")) {
        foreach my $p (getProtocolList('')) { 
		$subdir{'all'}{'protocol'}{$p}="${rrddir}/protocol_${p}.rrd";
		-f $subdir{'all'}{'protocol'}{$p} or &browserDie("Cannot find file $subdir{'all'}{'protocol'}{$p}");
	}
    }
    foreach my $s (getServiceList('')) { 
        if ( param("all_service_${s}")) {
        $subdir{'all'}{'service'}{$s}="${rrddir}/service_${s}";
        -f $subdir{'all'}{'service'}{$s}.'_src.rrd' or &browserDie("Cannot find file $subdir{'all'}{'service'}{$s}_src.rrd");
        -f $subdir{'all'}{'service'}{$s}.'_dst.rrd' or &browserDie("Cannot find file $subdir{'all'}{'service'}{$s}_dst.rrd");
        }
    }
    if (param("all_all_services")) {
        foreach my $s (getServiceList('')) { 
		$subdir{'all'}{'service'}{$s}="${rrddir}/service_${s}";
		-f $subdir{'all'}{'service'}{$s}.'_src.rrd' or &browserDie("Cannot find file $subdir{'all'}{'service'}{$s}_src.rrd");
		-f $subdir{'all'}{'service'}{$s}.'_dst.rrd' or &browserDie("Cannot find file $subdir{'all'}{'service'}{$s}_dst.rrd");
	}
    }
    foreach my $t (getTosList('')) { 
        if ( param("all_tos")) {
        $subdir{'all'}{'tos'}{$t}="${rrddir}/tos_${t}.rrd";
        -f $subdir{'all'}{'tos'}{$t} or &browserDie("Cannot find file $subdir{'all'}{'tos'}{$t}");
        }
    }
    if (param("all_all_tos")) {
        foreach my $t (getTosList('')) {
		$subdir{'all'}{'tos'}{$t}="${rrddir}/tos_${t}.rrd";
		-f $subdir{'all'}{'tos'}{$t} or &browserDie("Cannot find file $subdir{'all'}{'tos'}{$t}");
	}
    }
    foreach my $n (getNetworkList('')) { 
        if ( param("all_network_${n}")) {
        $subdir{'all'}{'network'}{$n}="${rrddir}/network_${n}.rrd";
        -f $subdir{'all'}{'network'}{$n} or &browserDie("Cannot find file $subdir{'all'}{'network'}{$n}");
        }
    }
    foreach my $n (param('all_network')) { 
        $subdir{'all'}{'network'}{$n}="${rrddir}/network_${n}.rrd";
        -f $subdir{'all'}{'network'}{$n} or &browserDie("Cannot find file $subdir{'all'}{'network'}{$n}");
    }
    if ( 	param("all_total") || param('all_network') || param('all_tos') || param('all_all_tos') || 
		param('all_protocol') || param('all_all_protocols') || param('all_service') || param('all_all_services') ) {
    	$subdir{'all'}{'total'}="${rrddir}/total.rrd";
    	-f $subdir{'all'}{'total'} or &browserDie("Cannot find file $subdir{'all'}{'total'}");
    }
}

# Generate list of available protocols
sub getProtocolList {
    my $rrd2dir = shift;
    $rrd2dir="/$rrd2dir";
    opendir( DIR, $rrddir.$rrd2dir ) or &browserDie("open $rrddir/$rrd2dir failed ($!)");
    @_ = grep { /^protocol_.*\.rrd$/ } readdir( DIR );
    closedir DIR;
    
    foreach (@_) {
	s/^protocol_(.*)\.rrd$/$1/;
    }

    return @_;
}

# Generate list of available services
sub getServiceList {
    my $rrd2dir;
    $rrd2dir = shift;
    $rrd2dir="/$rrd2dir";
    opendir( DIR, $rrddir.$rrd2dir ) or &browserDie("open $rrddir/$rrd2dir failed ($!)");
    @_ = grep { /^service_.*_src\.rrd$/ } readdir( DIR );
    closedir DIR;

    foreach (@_) {
	s/^service_(.*)_src\.rrd$/$1/;
    }

    return @_;
}

# Generate list of available TOS
sub getTosList {
    my $rrd2dir = shift;
    $rrd2dir="/$rrd2dir";
    opendir( DIR, $rrddir.$rrd2dir ) or &browserDie("open $rrddir failed ($!)");
    @_ = grep { /^tos_.*\.rrd$/ } readdir( DIR );
    closedir DIR;

    foreach (@_) {
	s/^tos_(.*)\.rrd$/$1/;
    }

    return @_;
}

# Generate list of available networks
sub getNetworkList {
    opendir( DIR, $rrddir ) or &browserDie("open $rrddir failed ($!)");
    @_ = grep { /^network_.*\.rrd$/ } readdir( DIR );
    closedir DIR;

    foreach (@_) {
	s/^network_(.*)\.rrd$/$1/;
    }

    return @_;
}


sub getHours {
    if( param('hours') ) {
	if( param('hours') =~ /^\d+$/ ) { $hours = param('hours') }
	else { &browserDie( "Invalid hours parameter" ) }
    }
}

sub getDuration {
    if( param('duration') ) {
	if( param('duration') =~ /^\d+$/ ) { $duration = param('duration') }
	else { &browserDie( "Invalid duration parameter" ) }
    } else { $duration = $hours; }
}

sub getWidth {
    if( param('width') ) {
	if( param('width') =~ /^\d+$/ ) { $width = param('width') }
	else { &browserDie( "Invalid width parameter" ) }
    }
}

sub getHeight {
    if( param('height') ) {
	if( param('height') =~ /^\d+$/ ) { $height = param('height') }
	else { &browserDie( "Invalid height parameter" ) }
    }
}

sub getDebug {
    if( param('debug') && param('debug') eq '1' ) {
	$debug = 1;
    } else { $debug = 0 }
}

sub doReport {
    defined param('report') or &browserDie( "You must specify report type" );

    return &generateImage( &io_report( param('report') ) );
}

## Assign each protocol/service a color

sub setColors {
    # "nice" colors. taken from Packeteer PacketShaper's web interface
    # (via Dave Plonka) and other places
    my @double_colors = ( 0xFF0000, # Red  
			0xFF6060,
			0x00FF00, # Green 
			0x60FF60,
			0x0000FF, # Blue
			0x6060FF,
			0xFFFF00, # Yellow
			0xFFFF90,
			0x808080, # Gray
  			0xA0A0A0, 
			0x993399, # Purple
			0xAA77AA, 
  			0xC09010, # Brown
  			0xD0B030, 
			0x645F9E, # Lavendel
  			0x8477BE, 
			0x000000, # Black
			0x404040, 
			0x709000, # Kaki
			0x90A000,
		        0x00D0D0, # Cyaan
		        0x80F0F0,
  			);
    
   my @safe_colors = ( 0xFF0000, # Red  
			0x00FF00, # Green 
			0x0000FF, # Blue
			0xFFFF00, # Yellow
			0x808080, # Gray
			0x993399, # Purple
  			0xC09010, # Brown
			0x746FAE, # lavender
		        );

	foreach my $type ('router','subnet') {
      		if (defined $subdir{$type}) {
	      		foreach my $r (keys %{$subdir{$type}}) {
                                if (defined $subdir{$type}{$r}{'service'}) {
					foreach my $s (keys %{$subdir{$type}{$r}{'service'}}) {
		    				$color{$r}{$s}{'src'} = &iterateColor(\@double_colors);
		    				$color{$r}{$s}{'dst'} = &iterateColor(\@double_colors);
					}
				}

                                if (defined $subdir{$type}{$r}{'protocol'}) {
					foreach my $p (keys %{$subdir{$type}{$r}{'protocol'}}) {
		    				$color{$r}{$p} = &iterateColor(\@safe_colors);
					}
				}
	
				if (defined $subdir{$type}{$r}{'tos'}) {
					foreach my $t (keys %{$subdir{$type}{$r}{'tos'}}) {
		    				$color{$r}{$t} = &iterateColor(\@safe_colors);
					}
				}
				$color{'total'}{$r} = &iterateColor(\@safe_colors);
	      		}
		}

	      	if (defined $subdir{'total_'.$type} && defined $subdir{'total_'.$type}{'protocol'}) {
	      		foreach my $p (keys %{$subdir{'total_'.$type}{'protocol'}}) {
		    		$color{$type}{$p} = &iterateColor(\@safe_colors);
	      		}
	      	}	

	      	if (defined $subdir{'total_'.$type} && defined $subdir{'total_'.$type}{'tos'}) {
	        	foreach my $t (keys %{$subdir{'total_'.$type}{'tos'}}) {
		    		$color{$type}{$t} = &iterateColor(\@safe_colors);
	        	}
	      	}

		$color{$type}{'total'} = &iterateColor(\@safe_colors);
	    }
	if (defined $subdir{'all'}) {
		foreach my $p (keys %{$subdir{'all'}{'protocol'}}) {
    			$color{'protocol'}{$p} = &iterateColor(\@safe_colors);
		}
		foreach my $s (keys %{$subdir{'all'}{'service'}}) {
    			$color{'service'}{$s}{'src'} = &iterateColor(\@double_colors);
    			$color{'service'}{$s}{'dst'} = &iterateColor(\@double_colors);
		}
		foreach my $n (keys %{$subdir{'all'}{'network'}}) {
    			$color{'network'}{$n} = &iterateColor(\@safe_colors);
		}
		foreach my $t (keys %{$subdir{'all'}{'tos'}}) {
    			$color{'tos'}{$t} = &iterateColor(\@safe_colors);
		}
	}
}

# use a color and move it to the back
sub iterateColor {
    my $color = shift @{$_[0]};
    push @{$_[0]}, $color;

    return sprintf('#%06x', $color);
}

# Generate list of available routers
sub getRouterList {
    opendir( DIR, $rrddir ) or &browserDie("open $rrddir failed ($!)");
    while( $_ = readdir( DIR ) ) {
        if( /^router_(.*)$/ ) {
		s/^router_(.*)$/$1/;
	if( !/^\.\.?/ && -d $rrddir.'/router_'.$_ ) {
		    push @_, $_;
		}
	}
    }
    closedir DIR;
    return @_;
}

# Generate list of available subnets
sub getSubnetList {
    opendir( DIR, $rrddir ) or &browserDie("open $rrddir failed ($!)");
    while( $_ = readdir( DIR ) ) {
        if( /^subnet_(.*)$/ ) {
        	s/^subnet_(.*)$/$1/;
		if( !/^\.\.?/ && -d $rrddir.'/subnet_'.$_ ) {
		    push @_, $_;
		}
	}
    }
    closedir DIR;
    return @_;
}

# rrdtool has annoying format rules so just use MD5 like cricket does
sub cleanDEF {
    my $def = shift;

    return $def if $debug;

    unless( exists $cdef{$def} ) {
	$cdef{$def} = substr( md5_hex($def), 0, 29);
    }
    return $cdef{$def};
}

# make service labels a consistent length
sub cleanServiceLabel {
    my $labelLength = 15;
    my $s = shift;
    my $txt = shift;
    return uc($s) . ' ' x ($labelLength - length $s) . $txt;
}

# make protocol labels a consistent length
sub cleanProtocolLabel {
    my $labelLength = 47;
    my $p = shift;
    return uc($p) . ' ' x ($labelLength - length $p);
}

# make other percentage labels a consistent length
sub cleanOtherLabel {
    my $labelLength = 51;
    my $label = shift;
    my $format = shift;
    return $label . ' ' x ($labelLength - length $label) . $format;
}

sub io_report {
    my $reportType = shift;
    my @args;
    my ($str1,$str2);

    unless( exists $reportName{$reportType} ) {
	&browserDie('invalid report parameter');
    }
    #push @args, Dumper(%subdir);

    push @args, ('--interlaced',
		 '--imgformat='.uc($imageType),
		 '--vertical-label='.$reportName{$reportType}.' per second',
		 "--title=${organization} Well Known Protocols/Services, ".
		 "\u${reportName{$reportType}}, +out/-in",
		 "--start=".(time - $hours*60*60),
		 "--end=".(time - $hours*60*60 + $duration*60*60),
		 "--width=${width}",
		 "--height=${height}",
		 '--alt-autoscale');

    foreach my $type ('router','subnet') {
        if (defined $subdir{'total_'.$type}) {
	        if( $reportType eq 'bits' ) {
		        push @args, ('DEF:'.&cleanDEF("${type}_total_out_bytes").'='.$subdir{'total_'.$type}{'total'}.':out_bytes:AVERAGE',
				     'DEF:'.&cleanDEF("${type}_total_in_bytes").'='.$subdir{'total_'.$type}{'total'}.':in_bytes:AVERAGE',
			  	     'CDEF:'.&cleanDEF("${type}_total_out_bits").'='.&cleanDEF("${type}_total_out_bytes").',8,*',
				     'CDEF:'.&cleanDEF("${type}_total_in_bits").'='.&cleanDEF("${type}_total_in_bytes").',8,*',
				     'CDEF:'.&cleanDEF("${type}_total_in_bits_neg").'='.&cleanDEF("${type}_total_in_bits").',-1,*');
		    } else {
		        push @args, ('DEF:'.&cleanDEF("${type}_total_out_${reportType}").'='.$subdir{'total_'.$type}{'total'}.":out_${reportType}:AVERAGE",
				     'DEF:'.&cleanDEF("${type}_total_in_${reportType}").'='.$subdir{'total_'.$type}{'total'}.":in_${reportType}:AVERAGE",
				     'CDEF:'.&cleanDEF("${type}_total_in_${reportType}_neg").'='.&cleanDEF("${type}_total_in_${reportType}").',-1,*');
		    }
	}
        # CDEFs for each protocol
	$str1 = 'CDEF:'.&cleanDEF("${type}_other_protocol_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${type}_other_protocol_out_pct").'=100';
        foreach my $p ( keys %{$subdir{'total_'.$type}{'protocol'}} ) {
	    if( $reportType eq 'bits' ) {
		push @args, ('DEF:'.&cleanDEF("${type}_${p}_out_bytes").'='.$subdir{'total_'.$type}{'protocol'}{$p}.':out_bytes:AVERAGE',
			     'DEF:'.&cleanDEF("${type}_${p}_in_bytes").'='.$subdir{'total_'.$type}{'protocol'}{$p}.':in_bytes:AVERAGE',
			     'CDEF:'.&cleanDEF("${type}_${p}_out_bits").'='.&cleanDEF("${type}_${p}_out_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${type}_${p}_in_bits").'='.&cleanDEF("${type}_${p}_in_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${type}_${p}_in_bits_neg").'='.&cleanDEF("${type}_${p}_in_bytes").',8,*,-1,*');
	    } else {
		push @args, ('DEF:'.&cleanDEF("${type}_${p}_out_${reportType}").'='.$subdir{'total_'.$type}{'protocol'}{$p}.":out_${reportType}:AVERAGE",
			     'DEF:'.&cleanDEF("${type}_${p}_in_${reportType}").'='.$subdir{'total_'.$type}{'protocol'}{$p}.":in_${reportType}:AVERAGE",
			     'CDEF:'.&cleanDEF("${type}_${p}_in_${reportType}_neg").'='.&cleanDEF("${type}_${p}_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("${type}_${p}_in_pct").'='.&cleanDEF("${type}_${p}_in_${reportType}").','.&cleanDEF("${type}_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("${type}_${p}_out_pct").'='.&cleanDEF("${type}_${p}_out_${reportType}").','.&cleanDEF("${type}_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("${type}_${p}_in_pct").',-';
	    $str2 .= ','.&cleanDEF("${type}_${p}_in_pct").',-';
	}
	if( scalar %{$subdir{'total_'.$type}{'protocol'}} ) {
		push @args, $str1;
		push @args, $str2;
        }
	
        # CDEFs for each service
	$str1 = 'CDEF:'.&cleanDEF("${type}_other_service_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${type}_other_service_out_pct").'=100';
	foreach my $s (keys %{$subdir{'total_'.$type}{'service'}}) {
	    if( $reportType eq 'bits' ) {
		push @args, (
			'DEF:'.&cleanDEF("${type}_${s}_src_out_bytes").'='.$subdir{'total_'.$type}{'service'}{$s}.'_src.rrd:out_bytes:AVERAGE',
			'DEF:'.&cleanDEF("${type}_${s}_src_in_bytes").'='.$subdir{'total_'.$type}{'service'}{$s}.'_src.rrd:in_bytes:AVERAGE',
			'DEF:'.&cleanDEF("${type}_${s}_dst_out_bytes").'='.$subdir{'total_'.$type}{'service'}{$s}.'_dst.rrd:out_bytes:AVERAGE',
			'DEF:'.&cleanDEF("${type}_${s}_dst_in_bytes").'='.$subdir{'total_'.$type}{'service'}{$s}.'_dst.rrd:in_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("${type}_${s}_src_out_bits").'='.&cleanDEF("${type}_${s}_src_out_bytes").',8,*',
			'CDEF:'.&cleanDEF("${type}_${s}_src_in_bits").'='.&cleanDEF("${type}_${s}_src_in_bytes").',8,*',
			'CDEF:'.&cleanDEF("${type}_${s}_src_in_bits_neg").'='.&cleanDEF("${type}_${s}_src_in_bytes").',8,*,-1,*',
			'CDEF:'.&cleanDEF("${type}_${s}_dst_out_bits").'='.&cleanDEF("${type}_${s}_dst_out_bytes").',8,*',
			'CDEF:'.&cleanDEF("${type}_${s}_dst_in_bits").'='.&cleanDEF("${type}_${s}_dst_in_bytes").',8,*',
			'CDEF:'.&cleanDEF("${type}_${s}_dst_in_bits_neg").'='.&cleanDEF("${type}_${s}_dst_in_bytes").',8,*,-1,*');
	    } else {
		push @args, (
			'DEF:'.&cleanDEF("${type}_${s}_src_out_${reportType}").'='.$subdir{'total_'.$type}{'service'}{$s}."_src.rrd:out_${reportType}:AVERAGE",
			'DEF:'.&cleanDEF("${type}_${s}_src_in_${reportType}").'='.$subdir{'total_'.$type}{'service'}{$s}."_src.rrd:in_${reportType}:AVERAGE",
			'DEF:'.&cleanDEF("${type}_${s}_dst_out_${reportType}").'='.$subdir{'total_'.$type}{'service'}{$s}."_dst.rrd:out_${reportType}:AVERAGE",
			'DEF:'.&cleanDEF("${type}_${s}_dst_in_${reportType}").'='.$subdir{'total_'.$type}{'service'}{$s}."_dst.rrd:in_${reportType}:AVERAGE",
			'CDEF:'.&cleanDEF("${type}_${s}_src_in_${reportType}_neg").'='.&cleanDEF("${type}_${s}_src_in_${reportType}").',-1,*',
			'CDEF:'.&cleanDEF("${type}_${s}_dst_in_${reportType}_neg").'='.&cleanDEF("${type}_${s}_dst_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("${type}_${s}_in_pct").'='.&cleanDEF("${type}_${s}_src_in_${reportType}").','.&cleanDEF("${type}_${s}_dst_in_${reportType}").',+,'.&cleanDEF("${type}_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("${type}_${s}_out_pct").'='.&cleanDEF("${type}_${s}_src_out_${reportType}").','.&cleanDEF("${type}_${s}_dst_out_${reportType}").',+,'.&cleanDEF("${type}_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("${type}_${s}_in_pct").',-';
   	    $str2 .= ','.&cleanDEF("${type}_${s}_out_pct").',-';
	}
	if( scalar %{$subdir{'total_'.$type}{'service'}} ) {
		push @args, $str1;
		push @args, $str2;
        }

        # CDEFs for each TOS
	$str1 = 'CDEF:'.&cleanDEF("${type}_other_tos_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${type}_other_tos_out_pct").'=100';
	foreach my $t (keys %{$subdir{'total_'.$type}{'tos'}} ) {
	    if( $reportType eq 'bits' ) {
		push @args, ('DEF:'.&cleanDEF("${type}_${t}_out_bytes").'='.$subdir{'total_'.$type}{'tos'}{$t}.':out_bytes:AVERAGE',
			     'DEF:'.&cleanDEF("${type}_${t}_in_bytes").'='.$subdir{'total_'.$type}{'tos'}{$t}.':in_bytes:AVERAGE',
			     'CDEF:'.&cleanDEF("${type}_${t}_out_bits").'='.&cleanDEF("${type}_${t}_out_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${type}_${t}_in_bits").'='.&cleanDEF("${type}_${t}_in_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${type}_${t}_in_bits_neg").'='.&cleanDEF("${type}_${t}_in_bytes").',8,*,-1,*');
	    } else {
		push @args, ('DEF:'.&cleanDEF("${type}_${t}_out_${reportType}").'='.$subdir{'total_'.$type}{'tos'}{$t}.":out_${reportType}:AVERAGE",
			     'DEF:'.&cleanDEF("${type}_${t}_in_${reportType}").'='.$subdir{'total_'.$type}{'tos'}{$t}.":in_${reportType}:AVERAGE",
			     'CDEF:'.&cleanDEF("${type}_${t}_in_${reportType}_neg").'='.&cleanDEF("${type}_${t}_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("${type}_${t}_in_pct").'='.&cleanDEF("${type}_${t}_in_${reportType}").','.&cleanDEF("${type}_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("${type}_${t}_out_pct").'='.&cleanDEF("${type}_${t}_out_${reportType}").','.&cleanDEF("${type}_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("${type}_${t}_in_pct").',-';
	    $str2 .= ','.&cleanDEF("${type}_${t}_out_pct").',-';
	}
	if( scalar %{$subdir{'total_'.$type}{'tos'}} ) {
		push @args, $str1;
		push @args, $str2;
	}


      # CDEF for total
      foreach my $r (keys %{$subdir{$type}}) {
	    if( $reportType eq 'bits' ) {
	        push @args, ('DEF:'.&cleanDEF("${r}_total_out_bytes").'='.$subdir{$type}{$r}{'total'}.':out_bytes:AVERAGE',
			     'DEF:'.&cleanDEF("${r}_total_in_bytes").'='.$subdir{$type}{$r}{'total'}.':in_bytes:AVERAGE',
		  	     'CDEF:'.&cleanDEF("${r}_total_out_bits").'='.&cleanDEF("${r}_total_out_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${r}_total_in_bits").'='.&cleanDEF("${r}_total_in_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${r}_total_in_bits_neg").'='.&cleanDEF("${r}_total_in_bits").',-1,*');
	    } else {
	        push @args, ('DEF:'.&cleanDEF("${r}_total_out_${reportType}").'='.$subdir{$type}{$r}{'total'}.":out_${reportType}:AVERAGE",
			     'DEF:'.&cleanDEF("${r}_total_in_${reportType}").'='.$subdir{$type}{$r}{'total'}.":in_${reportType}:AVERAGE",
			     'CDEF:'.&cleanDEF("${r}_total_in_${reportType}_neg").'='.&cleanDEF("${r}_total_in_${reportType}").',-1,*');
	    }
 
        # CDEFs for each protocol
	$str1 = 'CDEF:'.&cleanDEF("${r}_other_protocol_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${r}_other_protocol_out_pct").'=100';
        foreach my $p ( keys %{$subdir{$type}{$r}{'protocol'}} ) {
	    if( $reportType eq 'bits' ) {
		push @args, ('DEF:'.&cleanDEF("${r}_${p}_out_bytes").'='.$subdir{$type}{$r}{'protocol'}{$p}.':out_bytes:AVERAGE',
			     'CDEF:'.&cleanDEF("${r}_${p}_out_bits").'='.&cleanDEF("${r}_${p}_out_bytes").',8,*',
			     'DEF:'.&cleanDEF("${r}_${p}_in_bytes").'='.$subdir{$type}{$r}{'protocol'}{$p}.':in_bytes:AVERAGE',
			     'CDEF:'.&cleanDEF("${r}_${p}_in_bits").'='.&cleanDEF("${r}_${p}_in_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${r}_${p}_in_bits_neg").'='.&cleanDEF("${r}_${p}_in_bytes").',8,*,-1,*');
	    } else {
		push @args, ('DEF:'.&cleanDEF("${r}_${p}_out_${reportType}").'='.$subdir{$type}{$r}{'protocol'}{$p}.":out_${reportType}:AVERAGE",
			     'DEF:'.&cleanDEF("${r}_${p}_in_${reportType}").'='.$subdir{$type}{$r}{'protocol'}{$p}.":in_${reportType}:AVERAGE",
			     'CDEF:'.&cleanDEF("${r}_${p}_in_${reportType}_neg").'='.&cleanDEF("${r}_${p}_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("${r}_${p}_in_pct").'='.&cleanDEF("${r}_${p}_in_${reportType}").','.&cleanDEF("${r}_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("${r}_${p}_out_pct").'='.&cleanDEF("${r}_${p}_out_${reportType}").','.&cleanDEF("${r}_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("${r}_${p}_in_pct").',-';
	    $str2 .= ','.&cleanDEF("${r}_${p}_in_pct").',-';
	}
	if( scalar %{$subdir{$type}{$r}{'protocol'}} ) {
		push @args, $str1;
		push @args, $str2;
        }
	
        # CDEFs for each service
	$str1 = 'CDEF:'.&cleanDEF("${r}_other_service_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${r}_other_service_out_pct").'=100';
	foreach my $s (keys %{$subdir{$type}{$r}{'service'}}) {
	    if( $reportType eq 'bits' ) {
		push @args, (
			'DEF:'.&cleanDEF("${r}_${s}_src_out_bytes").'='.$subdir{$type}{$r}{'service'}{$s}.'_src.rrd:out_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("${r}_${s}_src_out_bits").'='.&cleanDEF("${r}_${s}_src_out_bytes").',8,*',
			'DEF:'.&cleanDEF("${r}_${s}_src_in_bytes").'='.$subdir{$type}{$r}{'service'}{$s}.'_src.rrd:in_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("${r}_${s}_src_in_bits").'='.&cleanDEF("${r}_${s}_src_in_bytes").',8,*',
			'CDEF:'.&cleanDEF("${r}_${s}_src_in_bits_neg").'='.&cleanDEF("${r}_${s}_src_in_bytes").',8,*,-1,*',
			'DEF:'.&cleanDEF("${r}_${s}_dst_out_bytes").'='.$subdir{$type}{$r}{'service'}{$s}.'_dst.rrd:out_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("${r}_${s}_dst_out_bits").'='.&cleanDEF("${r}_${s}_dst_out_bytes").',8,*',
			'DEF:'.&cleanDEF("${r}_${s}_dst_in_bytes").'='.$subdir{$type}{$r}{'service'}{$s}.'_dst.rrd:in_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("${r}_${s}_dst_in_bits").'='.&cleanDEF("${r}_${s}_dst_in_bytes").',8,*',
			'CDEF:'.&cleanDEF("${r}_${s}_dst_in_bits_neg").'='.&cleanDEF("${r}_${s}_dst_in_bytes").',8,*,-1,*');
	    } else {
		push @args, (
			'DEF:'.&cleanDEF("${r}_${s}_src_out_${reportType}").'='.$subdir{$type}{$r}{'service'}{$s}."_src.rrd:out_${reportType}:AVERAGE",
			'DEF:'.&cleanDEF("${r}_${s}_src_in_${reportType}").'='.$subdir{$type}{$r}{'service'}{$s}."_src.rrd:in_${reportType}:AVERAGE",
			'CDEF:'.&cleanDEF("${r}_${s}_src_in_${reportType}_neg").'='.&cleanDEF("${r}_${s}_src_in_${reportType}").',-1,*',
			'DEF:'.&cleanDEF("${r}_${s}_dst_out_${reportType}").'='.$subdir{$type}{$r}{'service'}{$s}."_dst.rrd:out_${reportType}:AVERAGE",
			'DEF:'.&cleanDEF("${r}_${s}_dst_in_${reportType}").'='.$subdir{$type}{$r}{'service'}{$s}."_dst.rrd:in_${reportType}:AVERAGE",
			'CDEF:'.&cleanDEF("${r}_${s}_dst_in_${reportType}_neg").'='.&cleanDEF("${r}_${s}_dst_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("${r}_${s}_in_pct").'='.&cleanDEF("${r}_${s}_src_in_${reportType}").','.&cleanDEF("${r}_${s}_dst_in_${reportType}").',+,'.&cleanDEF("${r}_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("${r}_${s}_out_pct").'='.&cleanDEF("${r}_${s}_src_out_${reportType}").','.&cleanDEF("${r}_${s}_dst_out_${reportType}").',+,'.&cleanDEF("${r}_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("${r}_${s}_in_pct").',-';
   	    $str2 .= ','.&cleanDEF("${r}_${s}_out_pct").',-';
	}
	if( scalar %{$subdir{$type}{$r}{'service'}} ) {
		push @args, $str1;
		push @args, $str2;
        }

        # CDEFs for each TOS
	$str1 = 'CDEF:'.&cleanDEF("${r}_other_tos_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${r}_other_tos_out_pct").'=100';
	foreach my $t (keys %{$subdir{$type}{$r}{'tos'}} ) {
	    if( $reportType eq 'bits' ) {
		push @args, ('DEF:'.&cleanDEF("${r}_${t}_out_bytes").'='.$subdir{$type}{$r}{'tos'}{$t}.':out_bytes:AVERAGE',
			     'DEF:'.&cleanDEF("${r}_${t}_in_bytes").'='.$subdir{$type}{$r}{'tos'}{$t}.':in_bytes:AVERAGE',
			     'CDEF:'.&cleanDEF("${r}_${t}_out_bits").'='.&cleanDEF("${r}_${t}_out_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${r}_${t}_in_bits").'='.&cleanDEF("${r}_${t}_in_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${r}_${t}_in_bits_neg").'='.&cleanDEF("${r}_${t}_in_bytes").',8,*,-1,*');
	    } else {
		push @args, ('DEF:'.&cleanDEF("${r}_${t}_out_${reportType}").'='.$subdir{$type}{$r}{'tos'}{$t}.":out_${reportType}:AVERAGE",
			     'DEF:'.&cleanDEF("${r}_${t}_in_${reportType}").'='.$subdir{$type}{$r}{'tos'}{$t}.":in_${reportType}:AVERAGE",
			     'CDEF:'.&cleanDEF("${r}_${t}_in_${reportType}_neg").'='.&cleanDEF("${r}_${t}_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("${r}_${t}_in_pct").'='.&cleanDEF("${r}_${t}_in_${reportType}").','.&cleanDEF("${r}_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("${r}_${t}_out_pct").'='.&cleanDEF("${r}_${t}_out_${reportType}").','.&cleanDEF("${r}_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("${r}_${t}_in_pct").',-';
	    $str2 .= ','.&cleanDEF("${r}_${t}_out_pct").',-';
	}
	if( scalar %{$subdir{$type}{$r}{'tos'}} ) {
		push @args, $str1;
		push @args, $str2;
	}
      }
    }
    
    if( defined $subdir{'all'}{'total'} ) {
	if( $reportType eq 'bits' ) {
	    push @args, ('DEF:'.&cleanDEF("all_total_out_bytes").'='.$subdir{'all'}{'total'}.':out_bytes:AVERAGE',
			 'CDEF:'.&cleanDEF("all_total_out_bits").'='.&cleanDEF("all_total_out_bytes").',8,*',
			 'DEF:'.&cleanDEF("all_total_in_bytes").'='.$subdir{'all'}{'total'}.':in_bytes:AVERAGE',
			 'CDEF:'.&cleanDEF("all_total_in_bits").'='.&cleanDEF("all_total_in_bytes").',8,*',
			 'CDEF:'.&cleanDEF("all_total_in_bits_neg").'='.&cleanDEF("all_total_in_bits").',-1,*');
	} else {
	    push @args, ('DEF:'.&cleanDEF("all_total_out_${reportType}").'='.$subdir{'all'}{'total'}.":out_${reportType}:AVERAGE",
			 'DEF:'.&cleanDEF("all_total_in_${reportType}").'='.$subdir{'all'}{'total'}.":in_${reportType}:AVERAGE",
			 'CDEF:'.&cleanDEF("all_total_in_${reportType}_neg").'='.&cleanDEF("all_total_in_${reportType}").',-1,*');
        }
    }
 
    # CDEFs for each all TOS
    $str1 = 'CDEF:'.&cleanDEF("all_other_protocol_in_pct").'=100';
    $str2 = 'CDEF:'.&cleanDEF("all_other_protocol_out_pct").'=100';
    foreach my $p (keys %{$subdir{'all'}{'protocol'}} ) {
	    if( $reportType eq 'bits' ) {
		push @args, ('DEF:'.&cleanDEF("all_${p}_out_bytes").'='.$subdir{'all'}{'protocol'}{$p}.':out_bytes:AVERAGE',
			     'DEF:'.&cleanDEF("all_${p}_in_bytes").'='.$subdir{'all'}{'protocol'}{$p}.':in_bytes:AVERAGE',
			     'CDEF:'.&cleanDEF("all_${p}_out_bits").'='.&cleanDEF("all_${p}_out_bytes").',8,*',
			     'CDEF:'.&cleanDEF("all_${p}_in_bits").'='.&cleanDEF("all_${p}_in_bytes").',8,*',
			     'CDEF:'.&cleanDEF("all_${p}_in_bits_neg").'='.&cleanDEF("all_${p}_in_bytes").',8,*,-1,*');
	    } else {
		push @args, ('DEF:'.&cleanDEF("all_${p}_out_${reportType}").'='.$subdir{'all'}{'protocol'}{$p}.":out_${reportType}:AVERAGE",
			     'DEF:'.&cleanDEF("all_${p}_in_${reportType}").'='.$subdir{'all'}{'protocol'}{$p}.":in_${reportType}:AVERAGE",
			     'CDEF:'.&cleanDEF("all_${p}_in_${reportType}_neg").'='.&cleanDEF("all_${p}_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("all_${p}_in_pct").'='.&cleanDEF("all_${p}_in_${reportType}").','.&cleanDEF("all_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("all_${p}_out_pct").'='.&cleanDEF("all_${p}_out_${reportType}").','.&cleanDEF("all_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("all_${p}_in_pct").',-';
	    $str2 .= ','.&cleanDEF("all_${p}_out_pct").',-';
    }
    if( scalar %{$subdir{'all'}{'protocol'}} ) {
	push @args, $str1;
	push @args, $str2;
    }

 
    # CDEFs for each all Service
    $str1 = 'CDEF:'.&cleanDEF("all_other_service_in_pct").'=100';
    $str2 = 'CDEF:'.&cleanDEF("all_other_service_out_pct").'=100';
    foreach my $s (keys %{$subdir{'all'}{'service'}} ) {
	    if( $reportType eq 'bits' ) {
		push @args, (
			'DEF:'.&cleanDEF("all_${s}_src_out_bytes").'='.$subdir{'all'}{'service'}{$s}.'_src.rrd:out_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("all_${s}_src_out_bits").'='.&cleanDEF("all_${s}_src_out_bytes").',8,*',
			'DEF:'.&cleanDEF("all_${s}_src_in_bytes").'='.$subdir{'all'}{'service'}{$s}.'_src.rrd:in_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("all_${s}_src_in_bits").'='.&cleanDEF("all_${s}_src_in_bytes").',8,*',
			'CDEF:'.&cleanDEF("all_${s}_src_in_bits_neg").'='.&cleanDEF("all_${s}_src_in_bytes").',8,*,-1,*',
			'DEF:'.&cleanDEF("all_${s}_dst_out_bytes").'='.$subdir{'all'}{'service'}{$s}.'_dst.rrd:out_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("all_${s}_dst_out_bits").'='.&cleanDEF("all_${s}_dst_out_bytes").',8,*',
			'DEF:'.&cleanDEF("all_${s}_dst_in_bytes").'='.$subdir{'all'}{'service'}{$s}.'_dst.rrd:in_bytes:AVERAGE',
			'CDEF:'.&cleanDEF("all_${s}_dst_in_bits").'='.&cleanDEF("all_${s}_dst_in_bytes").',8,*',
			'CDEF:'.&cleanDEF("all_${s}_dst_in_bits_neg").'='.&cleanDEF("all_${s}_dst_in_bytes").',8,*,-1,*');
	    } else {
		push @args, (
			'DEF:'.&cleanDEF("all_${s}_src_out_${reportType}").'='.$subdir{'all'}{'service'}{$s}."_src.rrd:out_${reportType}:AVERAGE",
			'DEF:'.&cleanDEF("all_${s}_src_in_${reportType}").'='.$subdir{'all'}{'service'}{$s}."_src.rrd:in_${reportType}:AVERAGE",
			'CDEF:'.&cleanDEF("all_${s}_src_in_${reportType}_neg").'='.&cleanDEF("all_${s}_src_in_${reportType}").',-1,*',
			'DEF:'.&cleanDEF("all_${s}_dst_out_${reportType}").'='.$subdir{'all'}{'service'}{$s}."_dst.rrd:out_${reportType}:AVERAGE",
			'DEF:'.&cleanDEF("all_${s}_dst_in_${reportType}").'='.$subdir{'all'}{'service'}{$s}."_dst.rrd:in_${reportType}:AVERAGE",
			'CDEF:'.&cleanDEF("all_${s}_dst_in_${reportType}_neg").'='.&cleanDEF("all_${s}_dst_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("all_${s}_in_pct").'='.&cleanDEF("all_${s}_src_in_${reportType}").','.&cleanDEF("all_${s}_dst_in_${reportType}").',+,'.&cleanDEF("all_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("all_${s}_out_pct").'='.&cleanDEF("all_${s}_src_out_${reportType}").','.&cleanDEF("all_${s}_dst_out_${reportType}").',+,'.&cleanDEF("all_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("all_${s}_in_pct").',-';
	    $str2 .= ','.&cleanDEF("all_${s}_out_pct").',-';
    }
    if( scalar %{$subdir{'all'}{'service'}} ) {
	push @args, $str1;
	push @args, $str2;
    }


    # CDEFs for each all TOS
    $str1 = 'CDEF:'.&cleanDEF("all_other_tos_in_pct").'=100';
    $str2 = 'CDEF:'.&cleanDEF("all_other_tos_out_pct").'=100';
    foreach my $t (keys %{$subdir{'all'}{'tos'}} ) {
	    if( $reportType eq 'bits' ) {
		push @args, ('DEF:'.&cleanDEF("all_${t}_out_bytes").'='.$subdir{'all'}{'tos'}{$t}.':out_bytes:AVERAGE',
			     'DEF:'.&cleanDEF("all_${t}_in_bytes").'='.$subdir{'all'}{'tos'}{$t}.':in_bytes:AVERAGE',
			     'CDEF:'.&cleanDEF("all_${t}_out_bits").'='.&cleanDEF("all_${t}_out_bytes").',8,*',
			     'CDEF:'.&cleanDEF("all_${t}_in_bits").'='.&cleanDEF("all_${t}_in_bytes").',8,*',
			     'CDEF:'.&cleanDEF("all_${t}_in_bits_neg").'='.&cleanDEF("all_${t}_in_bytes").',8,*,-1,*');
	    } else {
		push @args, ('DEF:'.&cleanDEF("all_${t}_out_${reportType}").'='.$subdir{'all'}{'tos'}{$t}.":out_${reportType}:AVERAGE",
			     'DEF:'.&cleanDEF("all_${t}_in_${reportType}").'='.$subdir{'all'}{'tos'}{$t}.":in_${reportType}:AVERAGE",
			     'CDEF:'.&cleanDEF("all_${t}_in_${reportType}_neg").'='.&cleanDEF("all_${t}_in_${reportType}").',-1,*');
	    }
	    push @args, 'CDEF:'.&cleanDEF("all_${t}_in_pct").'='.&cleanDEF("all_${t}_in_${reportType}").','.&cleanDEF("all_total_in_${reportType}").',/,100,*';
	    push @args, 'CDEF:'.&cleanDEF("all_${t}_out_pct").'='.&cleanDEF("all_${t}_out_${reportType}").','.&cleanDEF("all_total_out_${reportType}").',/,100,*';
	    $str1 .= ','.&cleanDEF("all_${t}_in_pct").',-';
	    $str2 .= ','.&cleanDEF("all_${t}_out_pct").',-';
    }
    if( scalar %{$subdir{'all'}{'tos'}} ) {
	push @args, $str1;
	push @args, $str2;
    }


    # CDEFs for each network
    $str1 = 'CDEF:'.&cleanDEF("all_other_network_in_pct").'=100';
    $str2 = 'CDEF:'.&cleanDEF("all_other_network_out_pct").'=100';
    foreach my $n (keys %{$subdir{'all'}{'network'}} ) {
	if( $reportType eq 'bits' ) {
	    push @args, ('DEF:'.&cleanDEF("all_${n}_out_bytes").'='.$subdir{'all'}{'network'}{$n}.':out_bytes:AVERAGE',
			 'DEF:'.&cleanDEF("all_${n}_in_bytes").'='.$subdir{'all'}{'network'}{$n}.':in_bytes:AVERAGE',
			 'CDEF:'.&cleanDEF("all_${n}_out_bits").'='.&cleanDEF("all_${n}_out_bytes").',8,*',
			 'CDEF:'.&cleanDEF("all_${n}_in_bits").'='.&cleanDEF("all_${n}_in_bytes").',8,*',
			 'CDEF:'.&cleanDEF("all_${n}_in_bits_neg").'='.&cleanDEF("all_${n}_in_bytes").',8,*,-1,*');
	} else {
	    push @args, ('DEF:'.&cleanDEF("all_${n}_out_${reportType}").'='.$subdir{'all'}{'network'}{$n}.":out_${reportType}:AVERAGE",
			 'DEF:'.&cleanDEF("all_${n}_in_${reportType}").'='.$subdir{'all'}{'network'}{$n}.":in_${reportType}:AVERAGE",
			 'CDEF:'.&cleanDEF("all_${n}_in_${reportType}_neg").'='.&cleanDEF("all_${n}_in_${reportType}").',-1,*');
	}
	push @args, 'CDEF:'.&cleanDEF("all_${n}_in_pct").'='.&cleanDEF("all_${n}_in_${reportType}").','.&cleanDEF("all_total_in_${reportType}").',/,100,*';
	push @args, 'CDEF:'.&cleanDEF("all_${n}_out_pct").'='.&cleanDEF("all_${n}_out_${reportType}").','.&cleanDEF("all_total_out_${reportType}").',/,100,*';
	$str1 .= ','.&cleanDEF("all_${n}_in_pct").',-';
	$str2 .= ','.&cleanDEF("all_${n}_out_pct").',-';
    }
    if( scalar %{$subdir{'all'}{'network'}} ) {
    	push @args, $str1;
    	push @args, $str2;
    }
    # Graph commands
    my $count;
    my $neg;

    foreach my $direction ('out','in') {
      if ($direction eq 'in') {
	$neg='_neg';
      } else {
	$neg='';
      }
      foreach my $type ('router','subnet') {

	$count = 0;
	foreach my $p (keys %{$subdir{'total_'.$type}{'protocol'}} ) {
		$count++;
		if( $count == 1 ) {
			push @args, 'AREA:'.&cleanDEF("${type}_${p}_".$direction."_".$reportType.$neg).$color{$type}{$p}.':'.&cleanProtocolLabel($p);
		} else {
			push @args, 'STACK:'.&cleanDEF("${type}_${p}_".$direction."_".$reportType.$neg).$color{$type}{$p}.':'.&cleanProtocolLabel($p);
		}
		if ($direction eq 'in') {
			push @args, 'GPRINT:'.&cleanDEF("${type}_${p}_out_pct").':AVERAGE:%.1lf%% Out';
			push @args, 'GPRINT:'.&cleanDEF("${type}_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
		}
	}

	# service outbound, percentages
	$count = 0;
	foreach my $s (keys %{$subdir{'total_'.$type}{'service'}} ) {
		$count++;
		if( $count == 1 ) {
			push @args, 'AREA:'.&cleanDEF("${type}_${s}_src_".$direction."_".$reportType.$neg).$color{$type}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
		} else {
			push @args, 'STACK:'.&cleanDEF("${type}_${s}_src_".$direction."_".$reportType.$neg).$color{$type}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
		}
    		push @args, 'STACK:'.&cleanDEF("${type}_${s}_dst_".$direction."_".$reportType.$neg).$color{$type}{$s}{'dst'}.':'.&cleanServiceLabel($s, ' dst  ');
		if ($direction eq 'in') {            
			push @args, 'GPRINT:'.&cleanDEF("${type}_${s}_out_pct").':AVERAGE:%.1lf%% Out';
			push @args, 'GPRINT:'.&cleanDEF("${type}_${s}_in_pct").':AVERAGE:%.1lf%% In\n',
		}
	}

	# tos outbound, percentages
	$count = 0;
	foreach my $t (keys %{$subdir{'total_'.$type}{'tos'}} ) {
 		$count++;
		if( $count == 1 ) {
			push @args, 'AREA:'.&cleanDEF("${type}_${t}_".$direction."_".$reportType.$neg).$color{$type}{$t}.':'.&cleanProtocolLabel($t);
		} else {
			push @args, 'STACK:'.&cleanDEF("${type}_${t}_".$direction."_".$reportType.$neg).$color{$type}{$t}.':'.&cleanProtocolLabel($t);
		}
		if ($direction eq 'in') {            
			push @args, 'GPRINT:'.&cleanDEF("${type}_${t}_out_pct").':AVERAGE:%.1lf%% Out';
			push @args, 'GPRINT:'.&cleanDEF("${type}_${t}_in_pct").':AVERAGE:%.1lf%% In\n',
		}
	}

        # total subnets routers, you must check on parameters, because total DEF,CDEF is often needed for %, but not requested 
	if (param ('total_'.$type.'_total') ) {
		push @args, 'LINE1:'.&cleanDEF("${type}_total_".$direction."_".$reportType.$neg).$color{$type}{'total'}.':TOTAL';
	}

        foreach my $r (keys %{$subdir{$type}}) {

		# protocol, percentages
		$count = 0;
		foreach my $p (keys %{$subdir{$type}{$r}{'protocol'}} ) {
			$count++;
			if( $count == 1 ) {
				push @args, 'AREA:'.&cleanDEF("${r}_${p}_".$direction."_".$reportType.$neg).$color{$r}{$p}.':'.&cleanProtocolLabel($p);
			} else {
				push @args, 'STACK:'.&cleanDEF("${r}_${p}_".$direction."_".$reportType.$neg).$color{$r}{$p}.':'.&cleanProtocolLabel($p);
			}
			if ($direction eq 'in') {
				push @args, 'GPRINT:'.&cleanDEF("${r}_${p}_out_pct").':AVERAGE:%.1lf%% Out';
				push @args, 'GPRINT:'.&cleanDEF("${r}_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
			}
		}

		# service, percentages
		$count = 0;
		foreach my $s (keys %{$subdir{$type}{$r}{'service'}} ) {
			$count++;
			if( $count == 1 ) {
				push @args, 'AREA:'.&cleanDEF("${r}_${s}_src_".$direction."_".$reportType.$neg).$color{$r}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
			} else {
				push @args, 'STACK:'.&cleanDEF("${r}_${s}_src_".$direction."_".$reportType.$neg).$color{$r}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
			}
	    		push @args, 'STACK:'.&cleanDEF("${r}_${s}_dst_".$direction."_".$reportType.$neg).$color{$r}{$s}{'dst'}.':'.&cleanServiceLabel($s, ' dst  ');
			if ($direction eq 'in') {            
				push @args, 'GPRINT:'.&cleanDEF("${r}_${s}_out_pct").':AVERAGE:%.1lf%% Out';
				push @args, 'GPRINT:'.&cleanDEF("${r}_${s}_in_pct").':AVERAGE:%.1lf%% In\n',
			}
		}

		# tos, percentages
		$count = 0;
		foreach my $t (keys %{$subdir{$type}{$r}{'tos'}} ) {
	 		$count++;
			if( $count == 1 ) {
				push @args, 'AREA:'.&cleanDEF("${r}_${t}_".$direction."_".$reportType.$neg).$color{$r}{$t}.':'.&cleanProtocolLabel($t);
			} else {
				push @args, 'STACK:'.&cleanDEF("${r}_${t}_".$direction."_".$reportType.$neg).$color{$r}{$t}.':'.&cleanProtocolLabel($t);
			}
			if ($direction eq 'in') {            
				push @args, 'GPRINT:'.&cleanDEF("${r}_${t}_out_pct").':AVERAGE:%.1lf%% Out';
				push @args, 'GPRINT:'.&cleanDEF("${r}_${t}_in_pct").':AVERAGE:%.1lf%% In\n',
			}
		}

                # total subnet router, you must check on parameters, because total DEF,CDEF is often needed for %, but not requested 
		if (param ($r.'_total') ) {
			push @args, 'LINE1:'.&cleanDEF("${r}_total_".$direction."_".$reportType.$neg).$color{'total'}{$r}.':TOTAL';
		}
        }
      }
      $count = 0;
      foreach my $p (keys %{$subdir{'all'}{'protocol'}} ) {
		$count++;
		if( $count == 1 ) {
			push @args, 'AREA:'.&cleanDEF("all_${p}_".$direction."_".$reportType.$neg).$color{'protocol'}{$p}.':'.&cleanProtocolLabel($p);
		} else {
			push @args, 'STACK:'.&cleanDEF("all_${p}_".$direction."_".$reportType.$neg).$color{'protocol'}{$p}.':'.&cleanProtocolLabel($p);
		}
		if ($direction eq 'in') {            
			push @args, 'GPRINT:'.&cleanDEF("all_${p}_out_pct").':AVERAGE:%.1lf%% Out';
			push @args, 'GPRINT:'.&cleanDEF("all_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
		}
      }
      $count = 0;
      foreach my $s (keys %{$subdir{'all'}{'service'}} ) {
		$count++;
		if( $count == 1 ) {
			push @args, 'AREA:'.&cleanDEF("all_${s}_src_".$direction."_".$reportType.$neg).$color{'service'}{$s}{'src'}.':'.&cleanProtocolLabel($s);
		} else {
			push @args, 'STACK:'.&cleanDEF("all_${s}_src_".$direction."_".$reportType.$neg).$color{'service'}{$s}{'src'}.':'.&cleanProtocolLabel($s);
		}
		push @args, 'STACK:'.&cleanDEF("all_${s}_dst_".$direction."_".$reportType.$neg).$color{'service'}{$s}{'dst'}.':'.&cleanProtocolLabel($s);
		if ($direction eq 'in') {            
			push @args, 'GPRINT:'.&cleanDEF("all_${s}_out_pct").':AVERAGE:%.1lf%% Out';
			push @args, 'GPRINT:'.&cleanDEF("all_${s}_in_pct").':AVERAGE:%.1lf%% In\n';
		}
      }
      $count = 0;
      foreach my $t (keys %{$subdir{'all'}{'tos'}} ) {
		$count++;
		if( $count == 1 ) {
			push @args, 'AREA:'.&cleanDEF("all_${t}_".$direction."_".$reportType.$neg).$color{'tos'}{$t}.':'.&cleanProtocolLabel($t);
		} else {
			push @args, 'STACK:'.&cleanDEF("all_${t}_".$direction."_".$reportType.$neg).$color{'tos'}{$t}.':'.&cleanProtocolLabel($t);
		}
		if ($direction eq 'in') {            
			push @args, 'GPRINT:'.&cleanDEF("all_${t}_out_pct").':AVERAGE:%.1lf%% Out';
			push @args, 'GPRINT:'.&cleanDEF("all_${t}_in_pct").':AVERAGE:%.1lf%% In\n';
		}
      }
      $count = 0;
      foreach my $n (keys %{$subdir{'all'}{'network'}} ) {
		$count++;
		if( $count == 1 ) {
			push @args, 'AREA:'.&cleanDEF("all_${n}_".$direction."_".$reportType.$neg).$color{'network'}{$n}.':'.&cleanProtocolLabel($n);
		} else {
			push @args, 'STACK:'.&cleanDEF("all_${n}_".$direction."_".$reportType.$neg).$color{'network'}{$n}.':'.&cleanProtocolLabel($n);
		}
		#push @args, 'STACK:'.&cleanDEF("all_${n}_".$direction."_".$reportType).$color{$n}.':'.&cleanProtocolLabel($n);
		if ($direction eq 'in') {            
			push @args, 'GPRINT:'.&cleanDEF("all_${n}_out_pct").':AVERAGE:%.1lf%% Out';
			push @args, 'GPRINT:'.&cleanDEF("all_${n}_in_pct").':AVERAGE:%.1lf%% In\n';
		}
      }
      if(param ('all_total')) {
		push @args, 'LINE1:'.&cleanDEF("all_total_".$direction."_".$reportType.$neg).'#000000:TOTAL';
      }
    }
    $count = 0;
    # network outbound, percentages
    # network other percentages
    if ( scalar %{$subdir{'all'}{'network'}} ) {
    	push @args, 'GPRINT:'.&cleanDEF("all_other_network_out_pct").':AVERAGE:'.&cleanOtherLabel('Other networks','%.1lf%% Out');
	push @args, 'GPRINT:'.&cleanDEF("all_other_network_in_pct").':AVERAGE:%.1lf%% In\n';
    }

#	# blank line after router
#	if( scalar @{$service{$r}} || scalar @{$protocol{$r}} || scalar @{$tos{$r}} ||
#	    exists $total{$r} ) {
#	    push @args, 'COMMENT:\n';
#	}
#    }

    push @args, 'HRULE:0#000000';
	
    return @args;
}
