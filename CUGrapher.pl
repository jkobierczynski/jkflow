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

#&getRouter();
#&getSubnet();
&getSubdir();
#&getProtocols("","");
#&getServices("","");
#&getTOS("","");
#    foreach my $r (@router) {
#	 &getProtocols($r,"router_");
#    }
#    foreach my $r (@subnet) {
#	 &getProtocols($r,"subnet_");
#    }
#    foreach my $r (@router) {
#	 &getServices($r,"router_");
#    }
#    foreach my $r (@subnet) {
#	 &getServices($r,"subnet_");
#    }
#    foreach my $r (@router) {
#	 &getTOS($r,"router_");
#    }
#    foreach my $r (@subnet) {
#	 &getTOS($r,"subnet_");
#    }
&getFilenames();
&getNetworks();
&getImageType();
&setColors();
&getHours();
&getDuration();
&getWidth();
&getHeight();
#&getTotal();
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

    print $q->Tr( { -align => 'center' },
		  $q->td( i('Routers') ),
		  $q->td( i('Protocol') ), $q->td( i('All Protos') ),
		  $q->td( i('Service') ), $q->td( i('All Svcs') ),
		  $q->td( i('TOS') ), $q->td( i('All TOS') ),
		  $q->td( i('Network') ),
		  $q->td( i('Total') ) );    


    foreach my $router (  sort &getRouterList() ) {
	print $q->start_Tr;

	print $q->td( { -align => 'center' }, $q->b($router),
		      $q->hidden( -name => 'router', -default => $router ));

	print $q->td( $q->scrolling_list( -name => "${router}_protocol",
					  -values => [sort &getProtocolList("router_".$router)],
					  -size => 5,
					  -multiple => 'true' ) );

	print $q->td( $q->checkbox( -name => "${router}_all_protocols",
				    -value => '1',
				    -label => 'Yes' ) );
	
	print $q->td( $q->scrolling_list( -name => "${router}_service",
					  -values => [sort &getServiceList("router_".$router)],
					  -size => 5,
					  -multiple => 'true' ) );

	print $q->td( $q->checkbox( -name => "${router}_all_services",
				    -value => '1',
				    -label => 'Yes' ) );

	print $q->td( $q->scrolling_list( -name => "${router}_tos",
					  -values => [sort &getTosList("router_".$router)],
					  -size => 5,
					  -multiple => 'true' ) );

	print $q->td( $q->checkbox( -name => "${router}_all_tos",
				    -value => '1',
				    -label => 'Yes' ) );

	if ($router eq 'all') {
	    print $q->td( $q->scrolling_list( -name => "${router}_network",
					      -values => [sort &getNetworkList()],
					      -size => 5,
					      -multiple => 'true' ) );
	} else {
	    print $q->td( '&nbsp;' );
	}
	
	print $q->td( $q->checkbox( -name => "${router}_total",
				    -value => '1',
				    -label => 'Yes') );
	
	print $q->end_Tr;
    }
    
    print $q->Tr( { -align => 'center' },
		  $q->td( i('Subnets') ),
		  $q->td( i('Protocol') ), $q->td( i('All Protos') ),
		  $q->td( i('Service') ), $q->td( i('All Svcs') ),
		  $q->td( i('TOS') ), $q->td( i('All TOS') ),
		  $q->td( i('Network') ),
		  $q->td( i('Total') ) );    

    foreach my $subnet ( sort &getSubnetList() ) {
        
	print $q->start_Tr;
	print $q->end_Tr;

	print $q->start_Tr;

	print $q->td( { -align => 'center' }, $q->b($subnet),
		      $q->hidden( -name => 'subnet', -default => $subnet ));

	print $q->td( $q->scrolling_list( -name => "${subnet}_protocol",
					  -values => [sort &getProtocolList("subnet_".$subnet)],
					  -size => 5,
					  -multiple => 'true' ) );

	print $q->td( $q->checkbox( -name => "${subnet}_all_protocols",
				    -value => '1',
				    -label => 'Yes' ) );
	
	print $q->td( $q->scrolling_list( -name => "${subnet}_service",
					  -values => [sort &getServiceList("subnet_".$subnet)],
					  -size => 5,
					  -multiple => 'true' ) );

	print $q->td( $q->checkbox( -name => "${subnet}_all_services",
				    -value => '1',
				    -label => 'Yes' ) );

	print $q->td( $q->scrolling_list( -name => "${subnet}_tos",
					  -values => [sort &getTosList("subnet_".$subnet)],
					  -size => 5,
					  -multiple => 'true' ) );

	print $q->td( $q->checkbox( -name => "${subnet}_all_tos",
				    -value => '1',
				    -label => 'Yes' ) );

	if ($subnet eq 'all') {
	    print $q->td( $q->scrolling_list( -name => "${subnet}_network",
					      -values => [sort &getNetworkList()],
					      -size => 5,
					      -multiple => 'true' ) );
	} else {
	    print $q->td( '&nbsp;' );
        }	

	print $q->td( $q->checkbox( -name => "${subnet}_total",
				    -value => '1',
				    -label => 'Yes') );
	
	print $q->end_Tr;
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

#sub getRouter {
#    if( !param('router') ) {
#	push @router, 'all';
#    }
#    # XXX how much is tainting a problem? .. attacks, etc
#    else {
#	foreach ( param('router') ) {
#	    s/\.\./_/g;
#	    if( $_ eq 'all' ) { push @router, 'all' }
#	    elsif( -d $rrddir.'/router_'.$_ ) { push @router, $_ }
#	    else { &browserDie('Invalid router parameter') }
#	}
#    }
#}

#sub getSubnet {
#    if( !param('subnet') ) {
#	push @subnet, 'all';
#    }
#    # XXX how much is tainting a problem? .. attacks, etc
#    else {
#	foreach ( param('subnet') ) {
#	    s/\.\./_/g;
#	    if( $_ eq 'all' ) { push @subnet, 'all' }
#	    elsif( -d $rrddir.'/subnet_'.$_ ) { push @subnet, $_ }
#	    else { &browserDie('Invalid subnet parameter') }
#	}
#    }
#}


### New getSubdir

sub getSubdir {
    foreach ( param('subnet') ) {
        s/\.\./_/g;
        if( $_ eq 'all') {
           if ( -d $rrddir.'/total_subnet' ) {
              $subdir{'total_subnet'}{'dir'} = '/total_subnet';
           }
           else {
           &browserDie('Total Subnet Directory not found:'.$rrddir.'/total_subnet');
           }
        }
        else {
           if ( -d $rrddir.'/subnet_'.$_ ) {
              $subdir{'subnet'}{$_}{'dir'} = '/'.$_;
           }
           else {
           &browserDie('Subnet Directory not found:'.$rrddir.'/'.$_);
           }
        }
    }
    foreach ( param('router') ) {
        s/\.\./_/g;
        if( $_ eq 'all') {
           if ( -d $rrddir.'/total_router' ) {
              $subdir{'total_router'}{'dir'} = '/total_router';
           }
           else {
           &browserDie('Total Router Directory not found:'.$rrddir.'/total_router')
           }
        }
        else {
           if ( -d $rrddir.'/router_'.$_ ) {
              $subdir{'router'}{$_}{'dir'} = '/'.$_;
           }
           else {
           &browserDie('Router Directory not found:'.$rrddir.'/'.$_);
           }
        }
    }
}
# Generate list of protocols and resolve filenames
sub getFilenames {
    foreach my $type ('router','subnet') {
        foreach my $r (keys %{$subdir{$type}}) {
            foreach my $p (param("${r}_protocol")) { 
#            foreach my $p (getProtocolList($type."_".$r)) { 
#                if ( param("${r}_protocol")) {
                $subdir{$type}{$r}{'protocol'}{$p}="${rrddir}/${type}_${r}/protocol_${p}.rrd";
                -f $subdir{$type}{$r}{'protocol'}{$p} or &browserDie("Cannot find file $subdir{$type}{$r}{'protocol'}{$p}");
#                }
            }
            if ( param("${r}_all_protocols")) {
                foreach my $p (getProtocolList($type."_".$r)) {
                $subdir{$type}{$r}{'protocol'}{$p}="${rrddir}/${type}_${r}/protocol_${p}.rrd";
                -f $subdir{$type}{$r}{'protocol'}{$p} or &browserDie("Cannot find file $subdir{$type}{$r}{'protocol'}{$p}");
                }
            }
            foreach my $s (param("${r}_service")) { 
#            foreach my $s (getServiceList($type."_".$r)) { 
#                if ( param("${r}_service")) {
                $subdir{$type}{$r}{'service'}{$s}="${rrddir}/${type}_${r}/service_${s}";
                -f $subdir{$type}{$r}{'service'}{$s}.'_src.rrd' or &browserDie("Cannot find file $subdir{$type}{$r}{'service'}{$s}");
                -f $subdir{$type}{$r}{'service'}{$s}.'_dst.rrd' or &browserDie("Cannot find file $subdir{$type}{$r}{'service'}{$s}");
#                }
            }
            if ( param("${r}_all_services")) {
                foreach my $s (getServiceList($type."_".$r)) {
                $subdir{$type}{$r}{'service'}{$s}="${rrddir}/${type}_${r}/service_${s}";
                -f $subdir{$type}{$r}{'service'}{$s}.'_src.rrd' or &browserDie("Cannot find file $subdir{$type}{$r}{'service'}{$s}");
                -f $subdir{$type}{$r}{'service'}{$s}.'_dst.rrd' or &browserDie("Cannot find file $subdir{$type}{$r}{'service'}{$s}");
                }
            }
            foreach my $t (param("${r}_tos")) { 
#            foreach my $t (getTosList($type."_".$r)) { 
#                if ( param("${r}_tos")) {
                $subdir{$type}{$r}{'tos'}{$t}="${rrddir}/${type}_${r}/tos_${t}.rrd";
                -f $subdir{$type}{$r}{'tos'}{$t} or &browserDie("Cannot find file $subdir{$type}{$r}{'tos'}{$t}");
#                }
            }
            if ( param("${r}_all_tos")) {
                foreach my $s (getTosList($type."_".$r)) {
                $subdir{$type}{$r}{'tos'}{$s}="${rrddir}/${type}_${r}/tos_${s}.rrd";
                -f $subdir{$type}{$r}{'tos'}{$s} or &browserDie("Cannot find file $subdir{$type}{$r}{'tos'}{$s}");
                -f $subdir{$type}{$r}{'tos'}{$s} or &browserDie("Cannot find file $subdir{$type}{$r}{'tos'}{$s}");
                }
            }
            if ( param("${r}_total")) {
            $subdir{$type}{$r}{'total'}="${rrddir}/${type}_${r}/total.rrd";
            -f $subdir{$type}{$r}{'total'} or &browserDie("Cannot find file $subdir{$type}{$r}{'total'}");
            }
        }
    }
    foreach my $r ('total_router','total_subnet') {
        foreach my $t (getTosList($r)) {
            if ( param("${r}_tos")) {
            $subdir{$r}{'tos'}{$t}="${rrddir}/${r}/tos_${t}.rrd";
            -f $subdir{$r}{'tos'}{$t} or &browserDie("Cannot find file $subdir{$r}{'tos'}{$t}");
            }
        }
        if ( param("${r}_total")) {
        $subdir{$r}{'total'}="${rrddir}/${r}/total.rrd";
        -f $subdir{$r}{'total'} or &browserDie("Cannot find file $subdir{$r}{'total'}");
        }
        if ( param("${r}_protocol_multicast")) {
        $subdir{$r}{'protocol'}{'multicast'}="${rrddir}/${r}/protocol_multicast.rrd";
        -f $subdir{$r}{'protocol'}{'multicast'} or &browserDie("Cannot find file $subdir{$r}{'protocol'}{'multicast'}");
        }
    }

    foreach my $p (getProtocolList('')) { 
        if ( param("protocol_all_${p}")) {
        $subdir{'all'}{'protocol'}{$p}="${rrddir}/protocol_${p}.rrd";
        -f $subdir{'all'}{'protocol'}{$p} or &browserDie("Cannot find file $subdir{'all'}{'protocol'}{$p}");
        }
    }
    foreach my $s (getServiceList('')) { 
        if ( param("service_all_${s}")) {
        $subdir{'all'}{'service'}{$s}="${rrddir}/service_${s}";
        -f $subdir{'all'}{'service'}{$s} or &browserDie("Cannot find file $subdir{'all'}{'service'}{$s}");
        }
    }
    foreach my $t (getTosList('')) { 
        if ( param("tos_all_${t}")) {
        $subdir{'all'}{'tos'}{$t}="${rrddir}/tos_${t}.rrd";
        -f $subdir{'all'}{'tos'}{$t} or &browserDie("Cannot find file $subdir{'all'}{'tos'}{$t}");
        }
    }
    foreach my $n (getNetworkList('')) { 
        if ( param("network_${n}")) {
        $subdir{'all'}{'network'}{$n}="${rrddir}/network_${n}.rrd";
        -f $subdir{'all'}{'network'}{$n} or &browserDie("Cannot find file $subdir{'all'}{'network'}{$n}");
        }
    }
    if ( param("total_all")) {
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
    opendir( DIR, $rrddir ) or &browserDie("open $rrddir failed ($!)");
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

#sub getTotal {
#    foreach my $r (@router) {
#	if( param("${r}_all") ) {
#	    $total{$r} = 1;
#	}
#	elsif( param("${r}_total") ) {
#	    $total{$r} = param("${r}_total");
#	}
#    }
#}

sub getDebug {
    if( param('debug') && param('debug') eq '1' ) {
	$debug = 1;
    } else { $debug = 0 }
}

sub doReport {
    defined param('report') or &browserDie( "You must specify report type" );

    return &generateImage( &io_report( param('report') ) );
}

# Generate list of protocols and resolve filenames
sub getProtocols {
    my $r=shift;
    my $type=shift;
#    foreach my $r (@router) {
        if( $r eq "all" && param("all_all_protocols") ) {
	    push @{$protocol{$r}}, &getProtocolList("");
	}
      	elsif( param("${r}_all_protocols") ) {
	    push @{$protocol{$r}}, &getProtocolList($type.$r);
	}
	elsif( param("${r}_protocol") ) {
	    push @{$protocol{$r}}, param("${r}_protocol");
	}
	foreach my $p ( @{$protocol{$r}} ) {
	    my $file;
	    if( $r eq 'all' ) 
		{
		$file = "${rrddir}/protocol_${p}.rrd";
		}
	    else { $file =  "${rrddir}/${type}${r}/protocol_${p}.rrd"}
	    -f $file or &browserDie("cannot find $file");

	    $filename{$r}{$p} = $file;
	}
	if( $r eq 'all' ) { $filename{$r}{'total'} = "${rrddir}/total.rrd" }
	else { 
		$filename{$r}{'total'} = "${rrddir}/${type}${r}/total.rrd";
		 }
#    }
}


# Generate list of services and resolve filenames
sub getServices {
    my $r=shift;
    my $type=shift;
#    foreach my $r (@router) {
        if( $r eq "all" && param("all_all_protocols") ) {
	    push @{$protocol{$r}}, &getProtocolList("");
	}
	if( param("${r}_all_services") ) {
	    push @{$service{$r}}, &getServiceList($type.$r);
	}
	elsif( param("${r}_service") ) {
	    push @{$service{$r}}, param("${r}_service");
	}
	foreach my $s ( @{$service{$r}} ) {
	    my ($file_base, $file_src, $file_dst);
	    if( $r eq 'all' ) {
		$file_base = "${rrddir}/service_${s}";
		$file_src = "${rrddir}/service_${s}_src.rrd";
		$file_dst = "${rrddir}/service_${s}_dst.rrd";
	    } else {
		$file_base = "${rrddir}/${type}${r}/service_${s}";
		$file_src = "${rrddir}/${type}${r}/service_${s}_src.rrd";
		$file_dst = "${rrddir}/${type}${r}/service_${s}_dst.rrd";
	    }
	    -f $file_src or &browserDie("cannot find $file_src");
	    -f $file_dst or &browserDie("cannot find $file_dst");
	    $filename{$r}{$s} = $file_base;
	}
#    }
}

# Generate list of TOS and resolve filenames
sub getTOS {
    my $r=shift;
    my $type=shift;
#    foreach my $r (@router) {
	if( param("${r}_all_tos") ) {
	    push @{$tos{$r}}, &getTosList();
	}
	elsif( param("${r}_tos") ) {
	    push @{$tos{$r}}, param("${r}_tos");
	}
	foreach my $t ( @{$tos{$r}} ) {
	    my $file;
	    if( $r eq 'all' ) { $file = "${rrddir}/tos_${t}.rrd"}
	    else { $file =  "${rrddir}/${type}${r}/tos_${t}.rrd"}
	    -f $file or &browserDie("cannot find $file");
	    $filename{$r}{$t} = $file;
	}
	if( $r eq 'all' ) { $filename{$r}{'total'} = "${rrddir}/total.rrd" }
	else { $filename{$r}{'total'} = "${rrddir}/${type}${r}/total.rrd" }
#   }
}
# Generate list of networks and resolve filenames
sub getNetworks {
    # Networks are only in the all category, for total traffic

    if( param("all_network") ) {
	push @{$network{'all'}}, param("all_network");
    }
    
    foreach my $n ( param("all_network") ) {
	my $file = "${rrddir}/network_${n}.rrd";

	-f $file or &browserDie("cannot find $file");

	$filename{'all'}{$n} = $file;
    }
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
      foreach my $r (keys %{$subdir{$type}}) {
	foreach my $s (keys %{$subdir{$type}{$r}{'service'}}) {
	    $color{$r}{$s}{'src'} = &iterateColor(\@double_colors);
	    $color{$r}{$s}{'dst'} = &iterateColor(\@double_colors);
	}

	foreach my $p (keys %{$subdir{$type}{$r}{'protocol'}}) {
	    $color{$r}{$p} = &iterateColor(\@safe_colors);
	}
	
	foreach my $t (keys %{$subdir{$type}{$r}{'tos'}}) {
	    $color{$r}{$t} = &iterateColor(\@safe_colors);
	}

	$color{$r}{'total'} = &iterateColor(\@safe_colors);
      }
    }
    foreach my $n (keys %{$subdir{'network'}}) {
    	$color{$n} = &iterateColor(\@safe_colors);
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

      # CDEF for total
      foreach my $r (keys %{$subdir{$type}}) {
        if (defined $subdir{$type}{$r}{'protocol'} || defined $subdir{$type}{$r}{'service'} || defined $subdir{$type}{$r}{'tos'}) { 
	    if( $reportType eq 'bits' ) {
	        push @args, ('DEF:'.&cleanDEF("${r}_total_out_bytes").'='.$subdir{$type}{$r}{'total'}.':out_bytes:AVERAGE',
		  	     'CDEF:'.&cleanDEF("${r}_total_out_bits").'='.&cleanDEF("${r}_total_out_bytes").',8,*',
			     'DEF:'.&cleanDEF("${r}_total_in_bytes").'='.$subdir{$type}{$r}{'total'}.':in_bytes:AVERAGE',
			     'CDEF:'.&cleanDEF("${r}_total_in_bits").'='.&cleanDEF("${r}_total_in_bytes").',8,*',
			     'CDEF:'.&cleanDEF("${r}_total_in_bits_neg").'='.&cleanDEF("${r}_total_in_bits").',-1,*');
	    } else {
	        push @args, ('DEF:'.&cleanDEF("${r}_total_out_${reportType}").'='.$subdir{$type}{$r}{'total'}.":out_${reportType}:AVERAGE",
			     'DEF:'.&cleanDEF("${r}_total_in_${reportType}").'='.$subdir{$type}{$r}{'total'}.":in_${reportType}:AVERAGE",
			     'CDEF:'.&cleanDEF("${r}_total_in_${reportType}_neg").'='.&cleanDEF("${r}_total_in_${reportType}").',-1,*');
	    }
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

    # Graph commands
    my $count;

    foreach my $type ('router','subnet') {
      foreach my $r (keys %{$subdir{$type}}) {
	
	push @args, 'COMMENT: '.$r.'\n';
	# tos outbound, percentages
	$count = 0;
	foreach my $t (keys %{$subdir{$type}{$r}{'tos'}} ) {
	    $count++;
            #push @args, "TOS $r @{$tos{$r}}\n";
	    if( $count == 1 ) {
		push @args, 'AREA:'.&cleanDEF("${r}_${t}_out_".$reportType).$color{$r}{$t}.':'.&cleanProtocolLabel($t);
	    } else {
		push @args, 'STACK:'.&cleanDEF("${r}_${t}_out_".$reportType).$color{$r}{$t}.':'.&cleanProtocolLabel($t);
	    }
	}

	# protocol outbound, percentages
	$count = 0;
	foreach my $p (keys %{$subdir{$type}{$r}{'protocol'}} ) {
	    $count++;
            #push @args, "Protocol $r @{$protocol{$r}}\n";
	    if( $count == 1 ) {
		push @args, 'AREA:'.&cleanDEF("${r}_${p}_out_".$reportType).$color{$r}{$p}.':'.&cleanProtocolLabel($p);
	    } else {
		push @args, 'STACK:'.&cleanDEF("${r}_${p}_out_".$reportType).$color{$r}{$p}.':'.&cleanProtocolLabel($p);
	    }
            push @args, 'GPRINT:'.&cleanDEF("${r}_${p}_out_pct").':AVERAGE:%.1lf%% Out';
            push @args, 'GPRINT:'.&cleanDEF("${r}_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
	}

	# service outbound, percentages
	$count = 0;
	foreach my $s (keys %{$subdir{$type}{$r}{'service'}} ) {
	    $count++;
            #push @args, "Service $r @{$service{$r}}\n";
	    if( $count == 1 ) {
		push @args, 'AREA:'.&cleanDEF("${r}_${s}_src_out_".$reportType).$color{$r}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
	    } else {
		push @args, 'STACK:'.&cleanDEF("${r}_${s}_src_out_".$reportType).$color{$r}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
	    }
	    push @args, 'STACK:'.&cleanDEF("${r}_${s}_dst_out_".$reportType).$color{$r}{$s}{'dst'}.':'.&cleanServiceLabel($s, ' dst  ');
            push @args, 'GPRINT:'.&cleanDEF("${r}_${s}_out_pct").':AVERAGE:%.1lf%% Out';
            push @args, 'GPRINT:'.&cleanDEF("${r}_${s}_in_pct").':AVERAGE:%.1lf%% In\n',
	}
        if (defined $subdir{$type}{$r}{'total'}) {
	   push @args, 'LINE1:'.&cleanDEF("${r}_total_out_".$reportType).$color{$r}{'total'}.':TOTAL';
	   push @args, 'LINE1:'.&cleanDEF("${r}_total_in_".$reportType.'_neg').$color{$r}{'total'}.':TOTAL';
        }
      }
    }
    $count = 0;
    # network outbound, percentages
    foreach my $n (keys %{$subdir{'network'}} ) {
    		$count++;
    		if( $count == 1 ) {
			push @args, 'AREA:'.&cleanDEF("all_${n}_out_".$reportType).$color{$n}.':'.&cleanProtocolLabel($n);
    		} else {
			push @args, 'STACK:'.&cleanDEF("all_${n}_out_".$reportType).$color{$n}.':'.&cleanProtocolLabel($n);
    		}
		push @args, 'STACK:'.&cleanDEF("all_${n}_out_".$reportType).$color{$n}.':'.&cleanProtocolLabel($n);
    		#push @args, 'GPRINT:'.&cleanDEF("all_${n}_out_pct").':AVERAGE:%.1lf%% Out\n';
    }
    # network other percentages
    if ( scalar %{$subdir{'network'}} ) {
    	push @args, 'GPRINT:'.&cleanDEF("all_other_network_out_pct").':AVERAGE:'.&cleanOtherLabel('Other networks','%.1lf%% Out');
    }

    # total outbound
    if( defined $subdir{'all'}{'total'} ) {
	push @args, 'LINE1:'.&cleanDEF("all_total_out_".$reportType).'#000000:TOTAL';
    }

    # Graph commands
    foreach my $type ('router','subnet') {
      foreach my $r (keys %{$subdir{$type}}) {
	
	$count = 0;
	# tos outbound, percentages
	foreach my $t (keys %{$subdir{$type}{$r}{'tos'}} ) {
	    $count++;
            #push @args, "TOS $r @{$tos{$r}}\n";
	    if( $count == 1 ) {
		push @args, 'AREA:'.&cleanDEF("${r}_${t}_in_".$reportType."_neg").$color{$r}{$t}.':'.&cleanProtocolLabel($t);
	    } else {
		push @args, 'STACK:'.&cleanDEF("${r}_${t}_in_".$reportType."_neg").$color{$r}{$t}.':'.&cleanProtocolLabel($t);
	    }
            push @args, 'GPRINT:'.&cleanDEF("${r}_${t}_out_pct").':AVERAGE:%.1lf%% Out';
            push @args, 'GPRINT:'.&cleanDEF("${r}_${t}_in_pct").':AVERAGE:%.1lf%% In\n';
	}

	# protocol outbound, percentages
	$count = 0;
	foreach my $p (keys %{$subdir{$type}{$r}{'protocol'}} ) {
	    $count++;
            #push @args, "Protocol $r @{$protocol{$r}}\n";
	    if( $count == 1 ) {
		push @args, 'AREA:'.&cleanDEF("${r}_${p}_in_".$reportType."_neg").$color{$r}{$p}.':'.&cleanProtocolLabel($p);
	    } else {
		push @args, 'STACK:'.&cleanDEF("${r}_${p}_in_".$reportType."_neg").$color{$r}{$p}.':'.&cleanProtocolLabel($p);
	    }
            push @args, 'GPRINT:'.&cleanDEF("${r}_${p}_out_pct").':AVERAGE:%.1lf%% Out';
            push @args, 'GPRINT:'.&cleanDEF("${r}_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
        }

	# service outbound, percentages
	$count = 0;
	foreach my $s (keys %{$subdir{$type}{$r}{'service'}} ) {
	    $count++;
            #push @args, "Service $r @{$service{$r}}\n";
	    if( $count == 1 ) {
		push @args, 'AREA:'.&cleanDEF("${r}_${s}_src_in_".$reportType."_neg").$color{$r}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
	    } else {
		push @args, 'STACK:'.&cleanDEF("${r}_${s}_src_in_".$reportType."_neg").$color{$r}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
	    }
	    push @args, 'STACK:'.&cleanDEF("${r}_${s}_dst_in_".$reportType."_neg").$color{$r}{$s}{'dst'}.':'.&cleanServiceLabel($s, ' dst  ');
            push @args, 'GPRINT:'.&cleanDEF("${r}_${s}_out_pct").':AVERAGE:%.1lf%% Out';
            push @args, 'GPRINT:'.&cleanDEF("${r}_${s}_in_pct").':AVERAGE:%.1lf%% In\n',
        }
      }
    }
    $count = 0;
    # network outbound, percentages
    foreach my $n (keys %{$subdir{'network'}} ) {
    	$count++;
    	if( $count == 1 ) {
		push @args, 'AREA:'.&cleanDEF("all_${n}_in_".$reportType."_neg").$color{$n}.':'.&cleanProtocolLabel($n);
    	} else {
		push @args, 'STACK:'.&cleanDEF("all_${n}_in_".$reportType."_neg").$color{$n}.':'.&cleanProtocolLabel($n);
    	}
	#if( scalar %{$subdir{'netwerk'}} ) {
        #    push @args, 'GPRINT:'.&cleanDEF("all_${n}_out_pct").':AVERAGE:%.1lf%% Out';
        #    push @args, 'GPRINT:'.&cleanDEF("all_${n}_in_pct").':AVERAGE:%.1lf%% In\n';
        #}

    }
    # network other percentages
    #if( scalar %{$subdir{'netwerk'}} ) {
    #	push @args, 'GPRINT:'.&cleanDEF("all_other_network_out_pct").':AVERAGE:'.&cleanOtherLabel('Other networks','%.1lf%% Out');
#	push @args, 'GPRINT:'.&cleanDEF("all_other_network_in_pct").':AVERAGE:%.1lf%% In\n';
 #   }

    # total outbound
    #if( defined $subdir{'all'}{'total'} ) {
#	push @args, 'LINE1:'.&cleanDEF("all_total_in_".$reportType.'_neg').'#000000:TOTAL';
#	push @args, 'LINE1:'.&cleanDEF("all_total_out_".$reportType).'#000000:TOTAL';
#    }
	
#	# blank line after router
#	if( scalar @{$service{$r}} || scalar @{$protocol{$r}} || scalar @{$tos{$r}} ||
#	    exists $total{$r} ) {
#	    push @args, 'COMMENT:\n';
#	}
#    }

    push @args, 'HRULE:0#000000';
	
    return @args;
}
