#!/usr/bin/perl -w

# JKGrapher.pl
# $Revision$
# Author: Jurgen Kobierczynski <jkobierczynski@hotmail.com>

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
my $organization = "Pharmacia WAN";
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

my @double_colors = (	0xFF0000, # Red  
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
    
my @single_colors = (	0xFF0000, # Red  
			0x00FF00, # Green 
			0x0000FF, # Blue
			0xFFFF00, # Yellow
			0x808080, # Gray
			0x993399, # Purple
			0xC09010, # Brown
			0x746FAE, # lavender
					);

my %double_list =	(
			in =>  [@double_colors] ,
			out => [@double_colors]  
					);

my %single_list =	(
			in =>  [@single_colors] ,
			out => [@single_colors] 
					);

if( !param() ) {
    &showList();
} elsif ( param("showlist") ) {
    &showMenu();
}

# protocol/service -> filename
my %filename;
# lists of networks/protocols/services/routers
my (%network, %protocol, %service, %tos, %subdir);
# should we show totals also?
my %total;
# hash for colors/CDEFs
my (%color, %cdef);
# are we in debug mode?
my $debug;
my @arg;

&fillSubdir();
&getImageType();
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

sub showList {
	my $q = new CGI::Pretty;
	my @list;
	print $q->header, $q->start_html( 	-title => 'Generate FlowScan graphs on the fly',
						-bgcolor => 'ffffff' );
	print $q->start_form( -action => $q->self_url, -method => 'get' );
	print $q->start_table( { 	-align => 'center',
					-border => '1'
					-cellspacing => '10' } );
	print $q->hidden( 	-name => 'showlist', 
				-default => "1" ); 
	print $q->Tr( { -align => 'center' },
		$q->td( i('Name') ),
		$q->td( i('Selected') ) );    
	foreach my $r ( getDirectoryList('')) {
		print $q->start_Tr;
		print $q->td( { -align => 'center' }, $r );
		print $q->td( $q->checkbox(	-name => 'subdir',
						-value => $r,
						-label => 'Yes') );
		print $q->end_Tr();
	}
	print $q->end_Tr();
	print $q->end_table();
	print $q->center( $q->submit(	-name => 'submit',
					-value => 'Select' ) );
	print $q->end_form();
	print $q->end_html;    
	exit;
}

sub showMenu {
	my $q = new CGI::Pretty;
	my @list;

	print $q->header, $q->start_html(	-title => 'Generate FlowScan graphs on the fly',
						-bgcolor => 'ffffff' );
	print $q->start_form( -action => $q->self_url, -method => 'get' );
	print $q->start_table( { 	-align => 'center',
					-cellspacing => '10' } );
	print $q->start_Tr( { 		-align => 'center',
					-valign => 'top' } );
	print $q->td( { 	-rowspan => '2' },
				"Report: ",
				$q->popup_menu( -name => 'report',
				-values => [sort keys %reportName],
				-default => '' ) );

	my %hours = ( 	6 => '6 hours',
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
		$q->popup_menu(	-name => 'imageType',
				-values => ['png', 'gif'],
				-default => 'png' ) );
    
	print $q->td( { -rowspan => '2' },
		"Width:",
		$q->textfield( 	-name => "width",
				-default => $width,
				-size => 7 ) );
    
	print $q->td( { -rowspan => '2' },
		"Height:",
		$q->textfield( 	-name => "height",
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

	print $q->start_table( { 	-align => 'center',
					-border => '1' } );

	print	$q->Tr( { -align => 'center' },
		$q->td( i('Stacked') ),
		$q->td( { -colspan => '2'}, $q->checkbox(-name => "protocol_stacked", -default=> '1', -value=> '1',-label => 'Yes' )),
		$q->td( { -colspan => '2'}, $q->checkbox(-name => "service_stacked", -value=> '1',-label => 'Yes' )),
		$q->td( { -colspan => '2'}, $q->checkbox(-name => "tos_stacked", -value=> '1',-label => 'Yes' )),
		$q->td( $q->checkbox(-name => "total_stacked", -value=> '1',-label => 'Yes' )));

	print	$q->Tr( { -align => 'center' },
		$q->td( i('Name') ),
		$q->td( i('Protocol') ), $q->td( i('All Protos') ),
		$q->td( i('Service') ), $q->td( i('All Svcs') ),
		$q->td( i('TOS') ), $q->td( i('All TOS') ),
		$q->td( i('Total') ) );    

	foreach my $r (param('subdir')) {
		print $q->start_Tr;
		print $q->td( { -align => 'center' }, $q->b($r));
		#$q->hidden( -name => $type, -default => $r ) );
		print $q->td( $q->scrolling_list(-name => "${r}_protocol",-values => [sort &getProtocolList($r)],-size => 5,-multiple => 'true' ) );
		print $q->td( $q->checkbox(-name => "${r}_all_protocols",-value => '1',-label => 'Yes' ) );
		print $q->td( $q->scrolling_list( -name => "${r}_service",-values => [sort &getServiceList($r)],-size => 5,-multiple => 'true' ) );
		print $q->td( $q->checkbox( -name => "${r}_all_services",-value => '1',-label => 'Yes' ) );
		print $q->td( $q->scrolling_list( -name => "${r}_tos",-values => [sort &getTosList($r)],-size => 5,-multiple => 'true' ) );
		print $q->td( $q->checkbox( -name => "${r}_all_tos",-value => '1',-label => 'Yes' ) );
		print $q->td( $q->checkbox( -name => "${r}_total",-value => '1',-label => 'Yes') );
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

sub getFilename {
	my $r = shift;
	my $subkey = shift;
	my $file=$rrddir;

	$file .= '/'.$r.'/'.$subkey;

        -f $file or &browserDie("Cannot find file $file, R=$r, Subkey=$subkey");
	return $file;
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

sub fillSubdir {
	foreach my $r ( getDirectoryList('') ) {
      		if (  	param($r.'_protocol') || param($r.'_all_protocols') ||
			param($r.'_service') || param($r.'_all_services') ||
			param($r.'_tos') || param($r.'_all_tos') ||
			param($r.'_total') ) {
 			if ( -d $rrddir.'/'.$r ) {
				$subdir{$r}{'dir'} = '/'.$r;
	   	        } else {
     				&browserDie('Subnet directory not found:'.$rrddir.'/'.$r);
	      		}
		}
		if ( param("${r}_all_protocols")) {
			foreach my $p (getProtocolList($r)) {
				$subdir{$r}{'protocol'}{$p}="${rrddir}/${r}/protocol_${p}.rrd";
			}
		}
		foreach my $p (param("${r}_protocol")) { 
			$subdir{$r}{'protocol'}{$p}="${rrddir}/${r}/protocol_${p}.rrd";
		}
		if ( param("${r}_all_services")) {
			foreach my $s (getServiceList($r)) {
				$subdir{$r}{'service'}{$s}="${rrddir}/${r}/service_${s}";
			}
		}
		foreach my $s (param("${r}_service")) { 
			$subdir{$r}{'service'}{$s}="${rrddir}/${r}/service_${s}";
		}
		if ( param("${r}_all_tos")) {
			foreach my $t (getTosList($r)) {
				$subdir{$r}{'tos'}{$t}="${rrddir}/${r}/tos_${t}.rrd";
			}
		}
		foreach my $t (param("${r}_tos")) { 
			$subdir{$r}{'tos'}{$t}="${rrddir}/${r}/tos_${t}.rrd";
		}
		#Dit moet altijd gebeuren voor de percentages if ( param("${r}_total")) {
		#	$subdir{$type}{$r}{'total'}="${rrddir}/${type}_${r}/total.rrd";
           	#}
	       	if ( 	param("${r}_protocol") || param("${r}_all_protocols")
			|| param("${r}_service") || param("${r}_all_services") 
       			|| param("${r}_tos") || param("${r}_all_tos") 
			|| param("${r}_total") ) {
				$subdir{$r}{'total'}="${rrddir}/${r}/total.rrd";
		}
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
    opendir( DIR, $rrddir.$rrd2dir ) or &browserDie("open ".$rrddir.$rrd2dir." failed ($!)");
    @_ = grep { /^tos_.*\.rrd$/ } readdir( DIR );
    closedir DIR;

    foreach (@_) {
	s/^tos_(.*)\.rrd$/$1/;
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

# use a color and move it to the back
sub iterateColor {
    my $color = shift @{$_[0]};
    push @{$_[0]}, $color;

    return sprintf('#%06x', $color);
}

sub getDirectoryList {
my $currentdir = shift;	
my @dirs;
	opendir(DIR, $rrddir.$currentdir) or &browserDie("open $currentdir failed ($!)");
        while( $_ = readdir( DIR ) ) {
		if (-d $rrddir.$currentdir.'/'.$_ && $_ ne '.' && $_ ne '..') {
			push @dirs,$_;
		}
	}
	closedir DIR;
	foreach my $dir (@dirs) {
		push @_, getDirectoryList($currentdir.'/'.$dir);
		push @_, $currentdir.'/'.$dir;
	}
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
    my $labelLength = 20;
    my $labelLength2 = 20;
    my $r = shift;
    my $s = shift;
    return uc($r) . ' ' x ($labelLength - length $r) . uc($s) . ' ' x ($labelLength2 - length $s); 
}

# make protocol labels a consistent length
sub cleanProtocolLabel {
    my $labelLength = 40;
    my $labelLength2 = 40;
    my $r = shift;
    my $p = shift;
    return uc($r) . ' ' x ($labelLength - length $r) . uc($p) . ' ' x ($labelLength2 - length $p);
}

# make other percentage labels a consistent length
sub cleanOtherLabel {
    my $labelLength = 51;
    my $label = shift;
    my $format = shift;
    return $label . ' ' x ($labelLength - length $label) . $format;
}

sub subreport {
	my $argref = shift;
	my $ref = shift;
	my $r = shift;
	my $reportType = shift;
	my ($str1,$str2);

	if( $reportType eq 'bits' ) {
		push @{$argref}, ('DEF:'.&cleanDEF("${r}_total_out_bytes").'='.&getFilename($r,'total.rrd').":out_bytes:AVERAGE",
		     'DEF:'.&cleanDEF("${r}_total_in_bytes").'='.&getFilename($r,'total.rrd').":in_bytes:AVERAGE",
	  	     'CDEF:'.&cleanDEF("${r}_total_out_bits").'='.&cleanDEF("${r}_total_out_bytes").',8,*',
		     'CDEF:'.&cleanDEF("${r}_total_in_bits").'='.&cleanDEF("${r}_total_in_bytes").',8,*',
		     'CDEF:'.&cleanDEF("${r}_total_in_bits_neg").'='.&cleanDEF("${r}_total_in_bits").',-1,*');
	} else {
		push @{$argref}, ('DEF:'.&cleanDEF("${r}_total_out_${reportType}").'='.&getFilename($r,'total.rrd').":out_${reportType}:AVERAGE",
		     'DEF:'.&cleanDEF("${r}_total_in_${reportType}").'='.&getFilename($r,'total.rrd').":in_${reportType}:AVERAGE",
		     'CDEF:'.&cleanDEF("${r}_total_in_${reportType}_neg").'='.&cleanDEF("${r}_total_in_${reportType}").',-1,*');
	}
 
	# CDEFs for each protocol
	$str1 = 'CDEF:'.&cleanDEF("${r}_other_protocol_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${r}_other_protocol_out_pct").'=100';
	foreach my $p ( keys %{$ref->{'protocol'}} ) {
		if( $reportType eq 'bits' ) {
			push @{$argref}, (
				'DEF:'.&cleanDEF("${r}_${p}_out_bytes").'='.&getFilename($r,'protocol_'.$p.'.rrd').":out_bytes:AVERAGE",
				'DEF:'.&cleanDEF("${r}_${p}_in_bytes").'='.&getFilename($r,'protocol_'.$p.'.rrd').":in_bytes:AVERAGE",
				'CDEF:'.&cleanDEF("${r}_${p}_out_bits").'='.&cleanDEF("${r}_${p}_out_bytes").',8,*',
				'CDEF:'.&cleanDEF("${r}_${p}_in_bits").'='.&cleanDEF("${r}_${p}_in_bytes").',8,*',
				'CDEF:'.&cleanDEF("${r}_${p}_in_bits_neg").'='.&cleanDEF("${r}_${p}_in_bytes").',8,*,-1,*');
		} else {
			push @{$argref}, (
				'DEF:'.&cleanDEF("${r}_${p}_out_${reportType}").'='.&getFilename($r,'protocol_'.$p.'.rrd').":out_${reportType}:AVERAGE",
				'DEF:'.&cleanDEF("${r}_${p}_in_${reportType}").'='.&getFilename($r,'protocol_'.$p.'.rrd').":in_${reportType}:AVERAGE",
				'CDEF:'.&cleanDEF("${r}_${p}_in_${reportType}_neg").'='.&cleanDEF("${r}_${p}_in_${reportType}").',-1,*');
		}
	push @{$argref}, 'CDEF:'.&cleanDEF("${r}_${p}_in_pct").'='.&cleanDEF("${r}_${p}_in_${reportType}").','.&cleanDEF("${r}_total_in_${reportType}").',/,100,*';
	push @{$argref}, 'CDEF:'.&cleanDEF("${r}_${p}_out_pct").'='.&cleanDEF("${r}_${p}_out_${reportType}").','.&cleanDEF("${r}_total_out_${reportType}").',/,100,*';
	$str1 .= ','.&cleanDEF("${r}_${p}_in_pct").',-';
	$str2 .= ','.&cleanDEF("${r}_${p}_in_pct").',-';
	}
	if( scalar %{$ref->{'protocol'}} ) {
		push @{$argref}, $str1;
		push @{$argref}, $str2;
	}

	# CDEFs for each service
	$str1 = 'CDEF:'.&cleanDEF("${r}_other_service_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${r}_other_service_out_pct").'=100';
	foreach my $s (keys %{$ref->{'service'}}) {
		if( $reportType eq 'bits' ) {
			push @{$argref}, (
				'DEF:'.&cleanDEF("${r}_${s}_src_out_bytes").'='.&getFilename($r,'service_'.$s.'_src.rrd').":out_bytes:AVERAGE",
				'DEF:'.&cleanDEF("${r}_${s}_src_in_bytes").'='.&getFilename($r,'service_'.$s.'_src.rrd').":in_bytes:AVERAGE",
				'CDEF:'.&cleanDEF("${r}_${s}_src_out_bits").'='.&cleanDEF("${r}_${s}_src_out_bytes").',8,*',
				'CDEF:'.&cleanDEF("${r}_${s}_src_in_bits").'='.&cleanDEF("${r}_${s}_src_in_bytes").',8,*',
				'CDEF:'.&cleanDEF("${r}_${s}_src_in_bits_neg").'='.&cleanDEF("${r}_${s}_src_in_bytes").',8,*,-1,*',
				'DEF:'.&cleanDEF("${r}_${s}_dst_out_bytes").'='.&getFilename($r,'service_'.$s.'_dst.rrd').":out_bytes:AVERAGE",
				'DEF:'.&cleanDEF("${r}_${s}_dst_in_bytes").'='.&getFilename($r,'service_'.$s.'_dst.rrd').":in_bytes:AVERAGE",
				'CDEF:'.&cleanDEF("${r}_${s}_dst_out_bits").'='.&cleanDEF("${r}_${s}_dst_out_bytes").',8,*',
				'CDEF:'.&cleanDEF("${r}_${s}_dst_in_bits").'='.&cleanDEF("${r}_${s}_dst_in_bytes").',8,*',
				'CDEF:'.&cleanDEF("${r}_${s}_dst_in_bits_neg").'='.&cleanDEF("${r}_${s}_dst_in_bytes").',8,*,-1,*');
		} else {
			push @{$argref}, (
				'DEF:'.&cleanDEF("${r}_${s}_src_out_${reportType}").'='.&getFilename($r,'service_'.$s.'_src.rrd').":out_${reportType}:AVERAGE",
				'DEF:'.&cleanDEF("${r}_${s}_src_in_${reportType}").'='.&getFilename($r,'service_'.$s.'_src.rrd').":in_${reportType}:AVERAGE",
				'CDEF:'.&cleanDEF("${r}_${s}_src_in_${reportType}_neg").'='.&cleanDEF("${r}_${s}_src_in_${reportType}").',-1,*',
				'DEF:'.&cleanDEF("${r}_${s}_dst_out_${reportType}").'='.&getFilename($r,'service_'.$s.'_dst.rrd').":out_${reportType}:AVERAGE",
				'DEF:'.&cleanDEF("${r}_${s}_dst_in_${reportType}").'='.&getFilename($r,'service_'.$s.'_dst.rrd').":in_${reportType}:AVERAGE",
				'CDEF:'.&cleanDEF("${r}_${s}_dst_in_${reportType}_neg").'='.&cleanDEF("${r}_${s}_dst_in_${reportType}").',-1,*');
    		}
		push @{$argref}, 'CDEF:'.&cleanDEF("${r}_${s}_in_pct").'='.&cleanDEF("${r}_${s}_src_in_${reportType}").','.&cleanDEF("${r}_${s}_dst_in_${reportType}").',+,'.&cleanDEF("${r}_total_in_${reportType}").',/,100,*';
		push @{$argref}, 'CDEF:'.&cleanDEF("${r}_${s}_out_pct").'='.&cleanDEF("${r}_${s}_src_out_${reportType}").','.&cleanDEF("${r}_${s}_dst_out_${reportType}").',+,'.&cleanDEF("${r}_total_out_${reportType}").',/,100,*';
		$str1 .= ','.&cleanDEF("${r}_${s}_in_pct").',-';
		$str2 .= ','.&cleanDEF("${r}_${s}_out_pct").',-';
	}
	if( scalar  %{$ref->{'service'}} ) {
		push @{$argref}, $str1;
		push @{$argref}, $str2;
	}

	# CDEFs for each TOS
	$str1 = 'CDEF:'.&cleanDEF("${r}_other_tos_in_pct").'=100';
	$str2 = 'CDEF:'.&cleanDEF("${r}_other_tos_out_pct").'=100';
	foreach my $t (keys  %{$ref->{'tos'}} ) {
		if( $reportType eq 'bits' ) {
			push @{$argref}, (
				'DEF:'.&cleanDEF("${r}_${t}_out_bytes").'='.&getFilename($r,'tos_'.$t.'.rrd').":out_bytes:AVERAGE",
				'DEF:'.&cleanDEF("${r}_${t}_in_bytes").'='.&getFilename($r,'tos_'.$t.'.rrd').":in_bytes:AVERAGE",
				'CDEF:'.&cleanDEF("${r}_${t}_out_bits").'='.&cleanDEF("${r}_${t}_out_bytes").',8,*',
				'CDEF:'.&cleanDEF("${r}_${t}_in_bits").'='.&cleanDEF("${r}_${t}_in_bytes").',8,*',
				'CDEF:'.&cleanDEF("${r}_${t}_in_bits_neg").'='.&cleanDEF("${r}_${t}_in_bytes").',8,*,-1,*');
		} else {
			push @{$argref}, (
				'DEF:'.&cleanDEF("${r}_${t}_out_${reportType}").'='.&getFilename($r,'tos_'.$t.'.rrd').":out_${reportType}:AVERAGE",
				'DEF:'.&cleanDEF("${r}_${t}_in_${reportType}").'='.&getFilename($r,'tos_'.$t.'.rrd').":in_${reportType}:AVERAGE",
				'CDEF:'.&cleanDEF("${r}_${t}_in_${reportType}_neg").'='.&cleanDEF("${r}_${t}_in_${reportType}").',-1,*');
		}
   		push @{$argref}, 'CDEF:'.&cleanDEF("${r}_${t}_in_pct").'='.&cleanDEF("${r}_${t}_in_${reportType}").','.&cleanDEF("${r}_total_in_${reportType}").',/,100,*';
		push @{$argref}, 'CDEF:'.&cleanDEF("${r}_${t}_out_pct").'='.&cleanDEF("${r}_${t}_out_${reportType}").','.&cleanDEF("${r}_total_out_${reportType}").',/,100,*';
		$str1 .= ','.&cleanDEF("${r}_${t}_in_pct").',-';
		$str2 .= ','.&cleanDEF("${r}_${t}_out_pct").',-';
	}
	if( scalar  %{$ref->{'tos'}} ) {
		push @{$argref}, $str1;
		push @{$argref}, $str2;
	}
#	}
}

sub plotreport {

	my $argsref = shift;
	my $ref = shift;
        my $basename = shift;
        my $reportType = shift;
	my $countref = shift;
	my ($neg,$string);

	foreach my $direction ('out','in') {
      		if ($direction eq 'in') {
			$neg='_neg';
		} else {
			$neg='';
		}
		foreach my $p (keys %{$ref->{'protocol'}} ) {
			if (defined param('protocol_stacked') && param('protocol_stacked') eq 1) {
				if( $countref->{protocol}{$direction} == 0 ) {
					$string = 'AREA:'.&cleanDEF($basename.'_'.$p.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
				} else {
					$string = 'STACK:'.&cleanDEF($basename.'_'.$p.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
				}
				$countref->{protocol}{$direction}++;
			} else {
				$string = 'LINE2:'.&cleanDEF($basename.'_'.$p.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
			}
      			if ($direction eq 'in') {
				push @{$argsref->{protocol}{in}}, $string.':'.cleanProtocolLabel($basename, $p);
				push @{$argsref->{protocol}{in}}, 'GPRINT:'.&cleanDEF("${basename}_${p}_out_pct").':AVERAGE:%.1lf%% Out';
				push @{$argsref->{protocol}{in}}, 'GPRINT:'.&cleanDEF("${basename}_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
			} else {
				push @{$argsref->{protocol}{out}}, $string;
			}
		
		}
	}

	foreach my $direction ('out','in') {
      		if ($direction eq 'in') {
			$neg='_neg';
		} else {
			$neg='';
		}
		foreach my $s (keys %{$ref->{'service'}} ) {
			foreach my $srcdst ('src','dst') {
				if (defined param('service_stacked') && param('service_stacked') eq 1) {
					if( $countref->{service}{$direction} == 0 ) {
						$string = 'AREA:'.&cleanDEF($basename.'_'.$s.'_'.$srcdst.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$double_list{$direction}});
					} else {
						$string = 'STACK:'.&cleanDEF($basename.'_'.$s.'_'.$srcdst.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$double_list{$direction}});
					}
					$countref->{service}{$direction}++;
				} else {
					$string = 'LINE2:'.&cleanDEF($basename.'_'.$s.'_'.$srcdst.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$double_list{$direction}});
				}
      				if ($direction eq 'in') {
					push @{$argsref->{service}{in}}, $string.':'.cleanServiceLabel($basename,$s.' '.$srcdst);
				} else {
					push @{$argsref->{service}{out}}, $string;
				}
			}
      			if ($direction eq 'in') {
				push @{$argsref->{service}{in}}, 'GPRINT:'.&cleanDEF("${basename}_${s}_out_pct").':AVERAGE:%.1lf%% Out';
				push @{$argsref->{service}{in}}, 'GPRINT:'.&cleanDEF("${basename}_${s}_in_pct").':AVERAGE:%.1lf%% In\n';
			}
		}
	}
	
	foreach my $direction ('out','in') {
      		if ($direction eq 'in') {
			$neg='_neg';
		} else {
			$neg='';
		}
		foreach my $t (keys %{$ref->{'tos'}} ) {
			if (defined param('tos_stacked') && param('tos_stacked') eq 1) {
				if( $countref->{tos}{$direction} == 0 ) {
					$string = 'AREA:'.&cleanDEF($basename.'_'.$t.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
				} else {
					$string = 'STACK:'.&cleanDEF($basename.'_'.$t.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
				}
				$countref->{tos}{$direction}++;
			} else {
				$string = 'LINE2:'.&cleanDEF($basename.'_'.$t.'_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
			}
      			if ($direction eq 'in') {
				push @{$argsref->{tos}{in}}, $string.':'.cleanProtocolLabel($basename,$t);
				push @{$argsref->{tos}{in}}, 'GPRINT:'.&cleanDEF("${basename}_${t}_out_pct").':AVERAGE:%.1lf%% Out';
				push @{$argsref->{tos}{in}}, 'GPRINT:'.&cleanDEF("${basename}_${t}_in_pct").':AVERAGE:%.1lf%% In\n';
			} else {
				push @{$argsref->{tos}{out}}, $string;
			}
					
		}
	}

	if (param ($basename.'_total') ) {
		foreach my $direction ('out','in') {
	      		if ($direction eq 'in') {
				$neg='_neg';
			} else {
				$neg='';
			}
			if (defined param('total_stacked') && param('total_stacked') eq 1 ) {
				if( $countref->{total}{$direction} == 0 ) {
					$string = 'AREA:'.&cleanDEF($basename.'_total_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
				} else {
					$string = 'STACK:'.&cleanDEF($basename.'_total_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
				}
				$countref->{total}{$direction}++;
			} else {
				$string = 'LINE2:'.&cleanDEF($basename.'_total_'.$direction.'_'.$reportType.$neg).&iterateColor(\@{$single_list{$direction}});
			}
	      		if ($direction eq 'in') {
				push @{$argsref->{total}{in}}, $string.':TOTAL '.$basename;
			} else {
				push @{$argsref->{total}{out}}, $string;
			}
		}
	}
}

sub io_report {
    my $reportType = shift;
    my ($str1,$str2);
	my %count;
	my %args;
	my @arg;

    unless( exists $reportName{$reportType} ) {
	&browserDie('invalid report parameter');
    }
    #push @args, Dumper(%subdir);

    push @arg, ('--interlaced',
		 '--imgformat='.uc($imageType),
		 '--vertical-label='.$reportName{$reportType}.' per second',
		 "--title=${organization} Well Known Protocols/Services, ".
		 "\u${reportName{$reportType}}, +out/-in",
		 "--start=".(time - $hours*60*60),
		 "--end=".(time - $hours*60*60 + $duration*60*60),
		 "--width=${width}",
		 "--height=${height}",
		 '--alt-autoscale');

	foreach my $r (keys %subdir) {
		subreport(\@arg,\%{$subdir{$r}},$r,$reportType);
	}

	#my $ref = shift;
        #my $basename = shift;
        #my $neg = shift;

	foreach my $r (keys %subdir) {
		#$count{protocol}{in}=0;
		#$count{protocol}{out}=0;
		#$count{service}{in}=0;
		#$count{service}{out}=0;
		#$count{tos}{in}=0;
		#$count{tos}{out}=0;
		#$count{total}{in}=0;
		#$count{total}{out}=0;
		plotreport(\%args,\%{$subdir{$r}},$r,$reportType,\%count);

	}

	if (defined $args{protocol}) 	{ push @arg, ( @{$args{protocol}{out}}, @{$args{protocol}{in}} ); }
	if (defined $args{service})  	{ push @arg, ( @{$args{service}{out}}, @{$args{service}{in}} ); }
	if (defined $args{tos})		{ push @arg, ( @{$args{tos}{out}}, @{$args{tos}{in}} );	 }
	if (defined $args{total})	{ push @arg, ( @{$args{total}{out}}, @{$args{total}{in}} );    }

    #my $count;
    #my $neg;

    #foreach my $direction ('out','in') {
    #  if ($direction eq 'in') {
	#$neg='_neg';
     # } else {
#	$neg='';
 #     }
  #    foreach my $type ('network','router','subnet') {
#
#	$count = 0;
#	foreach my $p (keys %{$subdir{'total_'.$type}{'protocol'}} ) {
#		$count++;
#		if( $count == 1 ) {
#			push @arg, 'AREA:'.&cleanDEF("total_${type}_${p}_".$direction."_".$reportType.$neg).$color{'total_'.$type}{$p}.':'.&cleanProtocolLabel($p);
#		} else {
#			push @arg, 'STACK:'.&cleanDEF("total_${type}_${p}_".$direction."_".$reportType.$neg).$color{'total_'.$type}{$p}.':'.&cleanProtocolLabel($p);
#		}
#		if ($direction eq 'in') {
#			push @arg, 'GPRINT:'.&cleanDEF("total_${type}_${p}_out_pct").':AVERAGE:%.1lf%% Out';
#			push @arg, 'GPRINT:'.&cleanDEF("total_${type}_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
#		}
#	}

#	# service outbound, percentages
#	$count = 0;
#	foreach my $s (keys %{$subdir{'total_'.$type}{'service'}} ) {
#		$count++;
#		if( $count == 1 ) {
#			push @arg, 'AREA:'.&cleanDEF("total_${type}_${s}_src_".$direction."_".$reportType.$neg).$color{'total_'.$type}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
#		} else {
#			push @arg, 'STACK:'.&cleanDEF("total_${type}_${s}_src_".$direction."_".$reportType.$neg).$color{'total_'.$type}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
#		}
 #   		push @arg, 'STACK:'.&cleanDEF("total_${type}_${s}_dst_".$direction."_".$reportType.$neg).$color{'total_'.$type}{$s}{'dst'}.':'.&cleanServiceLabel($s, ' dst  ');
#		if ($direction eq 'in') {            
#			push @arg, 'GPRINT:'.&cleanDEF("total_${type}_${s}_out_pct").':AVERAGE:%.1lf%% Out';
#			push @arg, 'GPRINT:'.&cleanDEF("total_${type}_${s}_in_pct").':AVERAGE:%.1lf%% In\n',
#		}
#	}

#	# tos outbound, percentages
#	$count = 0;
#	foreach my $t (keys %{$subdir{'total_'.$type}{'tos'}} ) {
 #		$count++;
#		if( $count == 1 ) {
#			push @arg, 'AREA:'.&cleanDEF("total_${type}_${t}_".$direction."_".$reportType.$neg).$color{'total_'.$type}{$t}.':'.&cleanProtocolLabel($t);
#		} else {
#			push @arg, 'STACK:'.&cleanDEF("total_${type}_${t}_".$direction."_".$reportType.$neg).$color{'total_'.$type}{$t}.':'.&cleanProtocolLabel($t);
#		}
#		if ($direction eq 'in') {            
#			push @arg, 'GPRINT:'.&cleanDEF("total_${type}_${t}_out_pct").':AVERAGE:%.1lf%% Out';
#			push @arg, 'GPRINT:'.&cleanDEF("total_${type}_${t}_in_pct").':AVERAGE:%.1lf%% In\n';
#		}
#	}

#        # total subnets routers, you must check on parameters, because total DEF,CDEF is often needed for %, but not requested 
#	if (param ('total_'.$type.'_total') ) {
#		push @arg, 'LINE1:'.&cleanDEF("total_${type}_total_".$direction."_".$reportType.$neg).$color{'total_'.$type}{'total'}.':TOTAL';
#	}
#
#       foreach my $r (keys %{$subdir{$type}}) {
#
#		# protocol, percentages
#		$count = 0;
#		foreach my $p (keys %{$subdir{$type}{$r}{'protocol'}} ) {
#			$count++;
#			if( $count == 1 ) {
#				push @arg, 'AREA:'.&cleanDEF("${r}_${p}_".$direction."_".$reportType.$neg).$color{$r}{$p}.':'.&cleanProtocolLabel($p);
#			} else {
#				push @arg, 'STACK:'.&cleanDEF("${r}_${p}_".$direction."_".$reportType.$neg).$color{$r}{$p}.':'.&cleanProtocolLabel($p);
#			}
#			if ($direction eq 'in') {
#				push @arg, 'GPRINT:'.&cleanDEF("${r}_${p}_out_pct").':AVERAGE:%.1lf%% Out';
#				push @arg, 'GPRINT:'.&cleanDEF("${r}_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
#			}
#		}

#		# service, percentages
#		$count = 0;
#		foreach my $s (keys %{$subdir{$type}{$r}{'service'}} ) {
#			$count++;
#			if( $count == 1 ) {
#				push @arg, 'AREA:'.&cleanDEF("${r}_${s}_src_".$direction."_".$reportType.$neg).$color{$r}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
#			} else {
#				push @arg, 'STACK:'.&cleanDEF("${r}_${s}_src_".$direction."_".$reportType.$neg).$color{$r}{$s}{'src'}.':'.&cleanServiceLabel($s, ' src  +');
#			}
#	    		push @arg, 'STACK:'.&cleanDEF("${r}_${s}_dst_".$direction."_".$reportType.$neg).$color{$r}{$s}{'dst'}.':'.&cleanServiceLabel($s, ' dst  ');
#			if ($direction eq 'in') {            
#				push @arg, 'GPRINT:'.&cleanDEF("${r}_${s}_out_pct").':AVERAGE:%.1lf%% Out';
#				push @arg, 'GPRINT:'.&cleanDEF("${r}_${s}_in_pct").':AVERAGE:%.1lf%% In\n',
#			}
#		}
#
#		# tos, percentages
#		$count = 0;
#		foreach my $t (keys %{$subdir{$type}{$r}{'tos'}} ) {
#	 		$count++;
#			if( $count == 1 ) {
#				push @arg, 'AREA:'.&cleanDEF("${r}_${t}_".$direction."_".$reportType.$neg).$color{$r}{$t}.':'.&cleanProtocolLabel($t);
#			} else {
#				push @arg, 'STACK:'.&cleanDEF("${r}_${t}_".$direction."_".$reportType.$neg).$color{$r}{$t}.':'.&cleanProtocolLabel($t);
#			}
#			if ($direction eq 'in') {            
#				push @arg, 'GPRINT:'.&cleanDEF("${r}_${t}_out_pct").':AVERAGE:%.1lf%% Out';
#				push @arg, 'GPRINT:'.&cleanDEF("${r}_${t}_in_pct").':AVERAGE:%.1lf%% In\n',
#			}
#		}
#
 #               # total subnet router, you must check on parameters, because total DEF,CDEF is often needed for %, but not requested 
#		if (param ($r.'_total') ) {
#			push @arg, 'LINE1:'.&cleanDEF("${r}_total_".$direction."_".$reportType.$neg).$color{'total'}{$r}.':TOTAL';
#		}
#       }
#      }
#      $count = 0;
#      foreach my $p (keys %{$subdir{'all'}{'protocol'}} ) {
#		$count++;
#		if( $count == 1 ) {
#			push @arg, 'AREA:'.&cleanDEF("all_${p}_".$direction."_".$reportType.$neg).$color{'protocol'}{$p}.':'.&cleanProtocolLabel($p);
#		} else {
#			push @arg, 'STACK:'.&cleanDEF("all_${p}_".$direction."_".$reportType.$neg).$color{'protocol'}{$p}.':'.&cleanProtocolLabel($p);
#		}
#		if ($direction eq 'in') {            
#			push @arg, 'GPRINT:'.&cleanDEF("all_${p}_out_pct").':AVERAGE:%.1lf%% Out';
#			push @arg, 'GPRINT:'.&cleanDEF("all_${p}_in_pct").':AVERAGE:%.1lf%% In\n';
#		}
#     }
#      $count = 0;
#      foreach my $s (keys %{$subdir{'all'}{'service'}} ) {
#		$count++;
#		if( $count == 1 ) {
#			push @arg, 'AREA:'.&cleanDEF("all_${s}_src_".$direction."_".$reportType.$neg).$color{'service'}{$s}{'src'}.':'.&cleanServiceLabel($s, " src +");
#		} else {
#			push @arg, 'STACK:'.&cleanDEF("all_${s}_src_".$direction."_".$reportType.$neg).$color{'service'}{$s}{'src'}.':'.&cleanServiceLabel($s," src +");
#		}
#		push @arg, 'STACK:'.&cleanDEF("all_${s}_dst_".$direction."_".$reportType.$neg).$color{'service'}{$s}{'dst'}.':'.&cleanServiceLabel($s," dst");
#		if ($direction eq 'in') {            
#			push @arg, 'GPRINT:'.&cleanDEF("all_${s}_out_pct").':AVERAGE:%.1lf%% Out';
#			push @arg, 'GPRINT:'.&cleanDEF("all_${s}_in_pct").':AVERAGE:%.1lf%% In\n';
#		}
#      }
#      $count = 0;
#      foreach my $t (keys %{$subdir{'all'}{'tos'}} ) {
#		$count++;
#		if( $count == 1 ) {
#			push @arg, 'AREA:'.&cleanDEF("all_${t}_".$direction."_".$reportType.$neg).$color{'tos'}{$t}.':'.&cleanProtocolLabel($t);
#		} else {
#			push @arg, 'STACK:'.&cleanDEF("all_${t}_".$direction."_".$reportType.$neg).$color{'tos'}{$t}.':'.&cleanProtocolLabel($t);
#		}
#		if ($direction eq 'in') {            
#			push @arg, 'GPRINT:'.&cleanDEF("all_${t}_out_pct").':AVERAGE:%.1lf%% Out';
#			push @arg, 'GPRINT:'.&cleanDEF("all_${t}_in_pct").':AVERAGE:%.1lf%% In\n';
#		}
#     }
#      $count = 0;
#      foreach my $n (keys %{$subdir{'all'}{'network'}} ) {
#		$count++;
#		if( $count == 1 ) {
#			push @arg, 'AREA:'.&cleanDEF("all_${n}_".$direction."_".$reportType.$neg).$color{'network'}{$n}.':'.&cleanProtocolLabel($n);
#		} else {
#			push @arg, 'STACK:'.&cleanDEF("all_${n}_".$direction."_".$reportType.$neg).$color{'network'}{$n}.':'.&cleanProtocolLabel($n);
#		}
#		#push @arg, 'STACK:'.&cleanDEF("all_${n}_".$direction."_".$reportType).$color{$n}.':'.&cleanProtocolLabel($n);
#		if ($direction eq 'in') {            
#			push @arg, 'GPRINT:'.&cleanDEF("all_${n}_out_pct").':AVERAGE:%.1lf%% Out';
#			push @arg, 'GPRINT:'.&cleanDEF("all_${n}_in_pct").':AVERAGE:%.1lf%% In\n';
#		}
#      }
#      if(param ('all_total')) {
#		push @arg, 'LINE1:'.&cleanDEF("all_total_".$direction."_".$reportType.$neg).'#000000:TOTAL';
#      }
#    }
#    $count = 0;
#    # network outbound, percentages
#    # network other percentages
#    if ( scalar %{$subdir{'all'}{'network'}} ) {
#    	push @arg, 'GPRINT:'.&cleanDEF("all_other_network_out_pct").':AVERAGE:'.&cleanOtherLabel('Other networks','%.1lf%% Out');
#	push @arg, 'GPRINT:'.&cleanDEF("all_other_network_in_pct").':AVERAGE:%.1lf%% In\n';
#    }

#	# blank line after router
#	if( scalar @{$service{$r}} || scalar @{$protocol{$r}} || scalar @{$tos{$r}} ||
#	    exists $total{$r} ) {
#	    push @arg, 'COMMENT:\n';
#	}
#    }

    push @arg, 'HRULE:0#000000';
	
    return @arg;
}