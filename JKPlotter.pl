#!/usr/bin/perl -w

# JKGrapher.pl
# $Revision$
# Author: Jurgen Kobierczynski <jkobierczynski@hotmail.com>

use strict;
use CGI::Pretty qw(-nosticky :standard);
use RRDs;
use Digest::MD5 qw(md5_hex);
use Data::Dumper;
use XML::Simple;
use DBM::Deep;
use Time::Local;
use GD;
use GD::Graph;
use GD::Graph::area;
use GD::Graph::lines;
use GD::Graph::bars;
use GD::Graph::mixed;

### It's a lot of "Filehandle GEN* opened only for input at
### /usr/lib/perl5/5.8.5/i386-linux-thread-multi/IO/Handle.pm line 399"
### messages, so just drop them. Comment these next lines if you have troubles!

BEGIN {
use CGI::Carp qw(carpout);
open (LOG, ">>/dev/null") or die "Carp doesn't load $!\n";
carpout(*LOG);
}

### Local settings ###

### Important: check the %definedcolors keys with /etc/services, or
### the default colors won't work! (these are defined for RedHat 9.0/Fedora)

# directory with rrd files
my $rrddir = "/var/flows/reports/rrds";
# directory with db files
my $dbdir = "/var/flows/reports/db";
# default number of hours to go back
my $hours = 48;
# duration of graph, starting from $hours ago
my $duration;
# organization name
my $organization = "Corporate WAN";
# default graph width
my $width = 1200;
# default graph height
my $height = 600;
# default image type (png/gif)
my $imageType = 'png';
# Sampleperiod = 300 seconds
my $sampleperiod = 300;

### End local settings ###
my $graphlegend = [];

# auto-flush STDOUT
$| = 1;
my $query = new CGI;
# Open latest JKFlow database
opendir(DIR, $dbdir) or &browserDie("open $dbdir failed ($!)");
my $latestdbfile = "0";
while ( $_ = readdir( DIR ) ) {
    if ($_ =~ /jkflow-10-(\d+).db/ && $1 > $latestdbfile) {
        $latestdbfile=$1;
    }
}
my $db = new DBM::Deep (
  file => $dbdir."/jkflow-10-".$latestdbfile.".db",
  mode => 'r' );

my $dbhash = {};

# report -> proper name
my %reporttype = ( 'bits' => 0,
                   'packets' => 2,
                   'flows' => 4);

my $randomcolors = [
     'lpurple','lorange','cyan','marine','lgreen','dpink','lyellow','gold',
     'lblue','green','pink','lbrown','red','blue','lorange','lbrown',
     'lred','dblue','dgray','dyellow','dgreen','dpink','lbrown','lgreen' ];

my $definedcolors = {
     'tcp' =>                   'blue',  # Blue
     'udp' =>                   'green', # Green
     'icmp' =>                  'cyan',  # Cyan
     'web_src' =>               'red',    'web_dst' =>             'lred',    # Red
     'secureweb_src' =>         'red',    'secureweb_dst' =>       'lred',    # Red
     'tcp_http_src' =>          'red',    'tcp_http_dst' =>        'lred',    # Red
     'ftp_src' =>               'yellow', 'ftp_dst' =>             'lyellow',  # Yellow
     'tcp_ftp_src' =>           'yellow', 'tcp_ftp_dst' =>         'lyellow',  # Yellow
     'tcp_ftp_src' =>           'yellow', 'tcp_ftp_dst' =>         'lyellow',  # Yellow
     'tcp_ftp-data_src' =>      'yellow', 'tcp_ftp-data_dst' =>    'lyellow',  # Yellow
     'tcp_netbios-ns_src' =>    'dblue',  'tcp_netbios-ns_dst' =>  'lblue',   # Blue
     'udp_netbios-ns_src' =>    'dblue',  'udp_netbios-ns_dst' =>  'lblue',   # Blue
     'tcp_netbios-dgm_src' =>   'dblue',  'tcp_netbios-dgm_dst' => 'lblue',   # Blue
     'udp_netbios-dgm_src' =>   'dblue',  'udp_netbios-dgm_dst' => 'lblue',   # Blue
     'tcp_netbios-ssn_src' =>   'dblue',  'tcp_netbios-ssn_dst' => 'lblue',   # Blue
     'udp_netbios-ssn_src' =>   'dblue',  'udp_netbios-ssn_dst' => 'lblue',   # Blue
     'windows_src' =>           'dblue',  'windows_dst' =>         'lblue',   # Blue
     'netbios_src' =>           'dblue',  'netbios_dst' =>         'lblue',   # Blue
     'dns_src' =>               'purple', 'dns_dst' =>             'lpurple', # Purple
     'tcp_telnet_src' =>        'gray',   'tcp_telnet_dst' =>      'lgray',   # Gray
     'tcp_ssh_src' =>           'gray',   'tcp_ssh_dst' =>         'lgray',   # Gray
     'mail_src' =>              'green',  'mail_dst' =>            'lgreen',  # Green
     'mailreading_src' =>       'green',  'mailreading_dst' =>     'lgreen',  # Green
     'tcp_imap_src' =>          'green',  'tcp_imap_dst' =>        'lgreen',  # Green
     'tcp_pop3_src' =>          'green',  'tcp_pop3_dst' =>        'lgreen',  # Green
     'tcp_x400_src' =>          'green',  'tcp_x400_dst' =>        'lgreen',  # Green-Gray
     'tcp_iso-tsap_src' =>      'green',  'tcp_iso-tsap_dst' =>    'lgreen',  # Green-Gray
     'tcp_iso_tsap_src' =>      'green',  'tcp_iso_tsap_dst' =>    'lgreen',  # Green-Gray
     'tcp_smtp_src' =>          'green',  'tcp_smtp_dst' =>        'lgreen',  # Green-Gray
     'tcp_nntp_src' =>          'brown',  'tcp_nntp_dst' =>        'lbrown',  # Brown
     'other_src' =>             'gray',   'other_dst' =>           'lgray',   # Gray
     'EF' =>                    'purple',  # Purple
     'AF41' =>                  'dyellow', # Yellow
     'AF42' =>                  'yellow',  # Yellow
     'AF43' =>                  'lyellow', # Yellow
     'AF31' =>                  'dred',    # Red
     'AF32' =>                  'red',     # Red
     'AF33' =>                  'lred',    # Red
     'AF21' =>                  'dgreen',  # Green
     'AF22' =>                  'green',   # Green
     'AF23' =>                  'lgreen',  # Green
     'AF11' =>                  'dblue',   # Blue
     'AF12' =>                  'blue',    # Blue
     'AF13' =>                  'lblue',   # Blue
     'CS1' =>                   'blue',    # Blue
     'CS2' =>                   'green',   # Green
     'CS3' =>                   'red',     # Red
     'CS4' =>                   'yellow',  # Yellow
     'CS5' =>                   'yellow',  # Yellow
     'CS6' =>                   'yellow',  # Yellow
     'CS7' =>                   'yellow',  # Yellow
     'BE' =>                    'gray',    # Gray
     'total' =>                 'black'    # Black
};


# protocol Directions
my @directions;

if (param('all_directions')) {
  @directions=&getDirectionList();
} else {
  @directions=param('direction');
 # if (param('direction') == 0) {
 #    &browserDie( "You must select directions" );
 # }
}

&getHours();
&getDuration();

if( !param() ) {
    &showList();
} elsif ( param("submit") ) {
    &getDBContent();
    &showMenu();
} elsif ( param("Reload") ) {
    &getDBContent();
    &showMenu();
}

# protocol/service -> filename
my %filename;
# lists of networks/protocols/services/routers
my (%network, %protocol, %service, %tos, %subdir, %config);
# should we show totals also?
my %total;
# hash for colors/CDEFs
my (%color, %cdef);
# are we in debug mode?
my $debug;
my @arg;

&getDBContent();
&fillSubdir();
&getImageType();
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
     print $q->header, $q->start_html( -title => 'Plot FlowScan graphs on the fly',
                                       -bgcolor => 'ffffff' );

     print $q->hidden( -name => 'showlist', 
                       -default => "1" ); 
     print $q->start_form( -action => $q->self_url, -method => 'get' ); 
     print $q->start_table( { -align => 'center', -cellspacing => '10'});
     print $q->h1( {-align => 'center'},'Plot FlowScan graphs on the fly');
     print $q->start_Tr( { -align => 'center' });
    #       print $q->td( { -align => 'center' }, $r );
    #       print $q->td( $q->checkbox( -name => 'subdir',
    #                                   -value => $r,
    #                                   -label => 'Yes') );
     print $q->td( $q->scrolling_list( -name => "direction", -values => [sort &getDirectionList()], -size => 10, -multiple => 'true' ) );
     print $q->td( $q->checkbox( -name => "all_directions", -value => '1', -label => 'All Directions' ) );
     print $q->end_Tr();
     print $q->end_table();
     print $q->center( $q->submit( -name => 'submit',
                                   -value => 'Select' ) );
     print $q->end_form();
     print $q->end_html;    
     exit;
}

sub showMenu {
     my $q = new CGI::Pretty;
     my @list;

     print $q->header, $q->start_html( -title => 'Plot FlowScan graphs on the fly',
                                       -bgcolor => 'ffffff' );
     print $q->start_form( -action => $q->self_url, 
                           -method => 'get' );

     print $q->hidden( -name => 'direction', 
                       -default => [ param('direction')]  );
     print $q->hidden( -name => 'all_directions', 
                       -default => [ param('all_directions')]  );

     print $q->start_table( { -align => 'center',
                              -cellspacing => '10',
                              -border => '0'} );
     print $q->start_Tr( { -align => 'center', 
                           -valign => 'top' } );
     print $q->td( { -rowspan => '2' },
                     "Report: ", $q->popup_menu( -name => 'report',
                                                 -values => [sort keys %reporttype],
                                                 -default => '' ) );
     print $q->td( { -align => 'right' },
                     "Time period: ", $q->textfield( -name => 'hours',
                                                     -value => 24 ) );
    
     print $q->td( { -rowspan => '1' },
                     "Image type: ", $q->popup_menu( -name => 'imageType',
                                                     -values => ['png', 'gif'],
                                                     -default => 'png' ) );
    
     print $q->td( { -rowspan => '1' },
                     "Width:", $q->textfield( -name => "width",
                                              -default => $width,
                                              -size => 7 ) );
    
     print $q->td( { -rowspan => '1' },
                     "Height:", $q->textfield( -name => "height",
                                               -default => $height,
                                               -size => 7 ) );

     print $q->end_Tr();
     print $q->start_Tr( { -align => 'center' } );

     print $q->td( { -align => 'right' },
                     "Duration: ", $q->textfield( -name => 'duration',
                                                  -value => 24 ) );

     print $q->td( { -rowspan => '1' },
                     "Predefined Colors: ", $q->checkbox( -name => "predefinedcolors",
                                                          -value => '1',
                                                          -checked => 'on',
                                                          -label => '' ));

     print $q->end_Tr();
     print $q->end_table();
     print $q->center( $q->submit( -name => '',-value => 'Generate graph' ),
                       $q->submit( -name => 'Reload',-value => 'Reload' ) );
      
     print $q->start_table( { -align => 'center',
                              -border => '1' } );

     print $q->Tr( { -align => 'center' },
           $q->td( i('Stacked') ),
           $q->td( { -colspan => '2'}, $q->checkbox(-name => "protocol_stacked", -default=>'1', -value=>'1', -label=>'Yes')),
           $q->td( { -colspan => '2'}, $q->checkbox(-name => "service_stacked", -default=>'1', -value=>'1', -label=>'Yes')),
           $q->td( { -colspan => '2'}, $q->checkbox(-name => "tos_stacked", -default=>'1', -value=>'1', -label=>'Yes')),
           $q->td( { -colspan => '2'}, $q->checkbox(-name => "tuples_stacked", -default=>'1', -value=>'1', -label=>'Yes')),
           $q->td( $q->checkbox(-name => "total_stacked", -default=>'1', -value=>'1', -label=>'Yes')));

     print $q->Tr( { -align => 'center' },
           $q->td( i('Name') ),
           $q->td( i('Protocol') ), $q->td( i('All Protos') ),
           $q->td( i('Service') ), $q->td( i('All Svcs') ),
           $q->td( i('TOS') ), $q->td( i('All TOS') ),
           $q->td( i('Tuples') ), $q->td( i('All Tuples') ),
           $q->td( i('Total') ) );    

     foreach my $direction (@directions) {
           print $q->start_Tr;
           print $q->td( { -align => 'center' }, $q->b($direction));
           print $q->td( $q->scrolling_list( 
            -name => "${direction}_protocol",
            -values => [sort {$config{protocol}{$direction}{$b} <=> $config{protocol}{$direction}{$a}} (keys %{$config{protocol}{$direction}})],
            -size => 5,-multiple => 'true' ) );
           print $q->td( $q->checkbox(-name => "${direction}_all_protocols",-value => '1',-label => 'Yes' ) );
           print $q->td( $q->scrolling_list(
            -name => "${direction}_service",
             -values => [sort {$config{service}{$direction}{$b} <=> $config{service}{$direction}{$a}} (keys %{$config{service}{$direction}})],
            -size => 5,-multiple => 'true' ) );
           print $q->td( $q->checkbox( -name => "${direction}_all_services",-value => '1',-label => 'Yes' ) );
           print $q->td( $q->scrolling_list(
            -name => "${direction}_tos",
            -values => [sort {$config{tos}{$direction}{$b} <=> $config{tos}{$direction}{$a}} (keys %{$config{tos}{$direction}})],
            -size => 5,-multiple => 'true' ) );
           print $q->td( $q->checkbox( -name => "${direction}_all_tos",-value => '1',-label => 'Yes' ) );
           print $q->td( $q->scrolling_list( 
            -name => "${direction}_tuples",
            -values => [sort {$config{tuples}{$direction}{$b} <=> $config{tuples}{$direction}{$a}} (keys %{$config{tuples}{$direction}})],
            -size => 5,-multiple => 'true' ) );
           print $q->td( $q->checkbox( -name => "${direction}_all_tuples",-value => '1',-label => 'Yes' ) );
           if (defined $config{total}{$direction}) {
             print $q->td( $q->checkbox( -name => "${direction}_total",-value => '1',-label => 'Yes') );
           } else {
             print $q->td( );
           }
           print $q->end_Tr;
     }

     print $q->end_table();
     print $q->center( $q->submit( -name => '',-value => 'Generate graph' ),
                       $q->submit( -name => 'Reload',-value => 'Reload' ) );
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
    print start_html( -title => 'Error Occurred',
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
     foreach my $direction ( @directions ) {
          if ( param("${direction}_all_protocols")) {
               foreach my $protocol (keys %{$config{protocol}{$direction}}) {
                    $subdir{'protocol'}{$direction}{$protocol}=1;
               }
          }
          foreach my $protocol (param("${direction}_protocol")) { 
               $subdir{'protocol'}{$direction}{$protocol}=1;
          }
          if ( param("${direction}_all_services")) {
               foreach my $service (keys %{$config{service}{$direction}}) {
                    $subdir{'service'}{$direction}{$service}=1;
               }
          }
          foreach my $service (param("${direction}_service")) { 
               $subdir{'service'}{$direction}{$service}=1;
          }
          if ( param("${direction}_all_tos")) {
               foreach my $tos (keys %{$config{tos}{$direction}}) {
                    $subdir{'tos'}{$direction}{$tos}=1;
               }
          }
          foreach my $tos (param("${direction}_tos")) { 
               $subdir{'tos'}{$direction}{$tos}=1;
          }
          if ( param("${direction}_all_tuples")) {
               foreach my $tuple (keys %{$config{tuples}{$direction}}) {
                    $subdir{'tuples'}{$direction}{$tuple}=1;
               }
          }
          foreach my $tuple (param("${direction}_tuples")) { 
               $subdir{'tuples'}{$direction}{$tuple}=1;
          }
          if (defined param("${direction}_total")) { 
               $subdir{'total'}{$direction}{total}=1;
          }
     }
}

# Genarate list of available directions
sub getDirectionList {
     @_ = sort keys %{$db->{config}};
}

# Generate list of available protocols
sub getProtocolList {
     my $direction = shift;	
     @_ = grep { s/^protocol_(.*)\.rrd$/$1/ } sort keys %{$db->{config}{$direction}};
}

# Generate list of available services
sub getServiceList {
my $direction = shift;	
     @_ = grep { s/^service_(.*)_src\.rrd$/$1/ } sort keys %{$db->{config}{$direction}};
}

# Generate list of available TOS/DSCP
sub getTosList {
my $direction = shift;
     @_ = grep { s/^tos_(.*)\.rrd$/$1/ } sort keys %{$db->{config}{$direction}};
}

# Generate list of available Tuples
sub getTuplesList {
my $direction = shift;
my $tuplelist = {};
    opendir(DIR, $dbdir) or &browserDie("open $dbdir failed ($!)");
    while( $_ = readdir( DIR ) ) {
      if ($_ =~ m/jkflow-(\d+)-(\d+).db/ &&  time - $hours*60*60 - $1*$sampleperiod < $2 && time - $hours*60*60 + $duration*60*60 > $2 ) {
        my $dbtemp = new DBM::Deep (
          file => $dbdir."/".$_,
          mode => 'r'
        );
        foreach my $tuple (keys %{$dbtemp->{config}{$direction}{tuples}}) {
            $tuplelist->{$tuple}=1;
        }
      }
    }
    closedir DIR;
    return sort keys %{$tuplelist};
}

sub getDBContent {
    opendir(DIR, $dbdir) or &browserDie("open $dbdir failed ($!)");
    while( $_ = readdir( DIR ) ) {
      if ($_ =~ m/jkflow-(\d+)-(\d+).db/ &&  time - $hours*60*60 - $1*$sampleperiod < $2 && time - $hours*60*60 + $duration*60*60 > $2 ) {
        my $dbtemp = new DBM::Deep (
          file => $dbdir."/".$_,
          mode => 'r'
        );
        foreach my $direction ( @directions ) {
          foreach my $protocol (keys %{$dbtemp->{config}{$direction}{protocol}}) {
             $config{protocol}{$direction}{$protocol}+=$dbtemp->{config}{$direction}{protocol}{$protocol};
          }
          foreach my $service (keys %{$dbtemp->{config}{$direction}{service}}) {
             $config{service}{$direction}{$service}+=$dbtemp->{config}{$direction}{service}{$service};
          }
          foreach my $tos (keys %{$dbtemp->{config}{$direction}{tos}}) {
             $config{tos}{$direction}{$tos}+=$dbtemp->{config}{$direction}{tos}{$tos};
          }
          foreach my $tuple (keys %{$dbtemp->{config}{$direction}{tuples}}) {
             $config{tuples}{$direction}{$tuple}+=$dbtemp->{config}{$direction}{tuples}{$tuple};
          }
          if (defined $dbtemp->{config}{$direction}{total}{total}) {
             $config{total}{$direction}{total}=1;
          }
        }
      }
    }
    closedir DIR;
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
    my %count;
    plotreport(\%subdir,$reporttype{param('report')},\%count);

}

# use a color and move it to the back
#sub iterateColor {
#    my $color = shift @{$_[0]};
#    push @{$_[0]}, $color;
#
#    return sprintf('#%06x', $color);
#}

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
    my $labelLength = 40;
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

sub getDirectoryList {
	opendir(DIR, $dbdir) or &browserDie("open $dbdir failed ($!)");
        while( $_ = readdir( DIR ) ) {
		if ($_ =~ m/jkflow-(\d+)-(\d+).db/ &&  time - $hours*60*60 - $1*$sampleperiod < $2 && time - $hours*60*60 + $duration*60*60 > $2 ) {
			my $dbtemp = new DBM::Deep (
				file => $dbdir."/".$_,
				mode => 'r' );
			foreach my $time (keys %{$dbtemp->{data}}) {
				if (time - $hours*60*60 < $time && time - $hours*60*60 + $duration*60*60 > $time ) {
					$dbhash->{data}{$time}=\%{$dbtemp->{data}{$time}};
				}
			}
		}
		#unshift @{$graphlegend}, time - $hours*60*60 + $duration*60*60; 
	}
	closedir DIR;
	return @_;
}


sub plotreport {

     my $subdir = shift;
     my $reporttype = shift;
     my $countref = shift;
     my ($neg,$string);
     
     my $graphdata = [];
     my $graphtype = [];
     my $graphcolor = [];
     my @times;
     my @timestrings;
     
     my $div=1;
     if ($reporttype==0) {
          $div = $db->{sampletime} / 8;
     } else {
          $div = $db->{sampletime};
     }
     
     &getDirectoryList();
     push @times, sort keys %{$dbhash->{data}};
     foreach my $which ('out','in') {
           if (param('total_stacked')) {
               my $totalvaluesaccumulated=[];
               foreach my $direction (sort keys %{$subdir{total}} ) {
                    my $totalvalues=[];
                    my $i=0;
                    foreach my $time (@times) {
                         if (defined @{$dbhash->{data}{$time}{$direction}{total}{'total'}}) {
                              if ($which eq 'in') {
                                   $totalvaluesaccumulated->[$i] -= ${$dbhash->{data}{$time}{$direction}{total}{'total'}}[0+$reporttype]/$div;
                              } else {
                                   $totalvaluesaccumulated->[$i] += ${$dbhash->{data}{$time}{$direction}{total}{'total'}}[1+$reporttype]/$div;
                              }
                         } else {
                              $totalvaluesaccumulated->[$i] += 0;
                         }
                         $i++;
                    }
                    push @{$totalvalues},@{$totalvaluesaccumulated};
                    unshift @{$graphdata},$totalvalues;
                    unshift @{$graphtype},'area';
                    if (param('predefinedcolors')) {
                         unshift @{$graphcolor}, $definedcolors->{'total'};
                    } else {
                         unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                    }
                    if ($which eq 'out') {
                         unshift @{$graphlegend}, "Total ".$direction;
                    } else {
                         unshift @{$graphlegend}, undef;
                    }
               }
          } else {
               foreach my $direction (sort keys %{$subdir{total}} ) {
                    my $totalvalues=[];
                    foreach my $time (@times) {
                         if (defined @{$dbhash->{data}{$time}{$direction}{total}{'total'}}) {
                              if ($which eq 'in') {
                                   push @{$totalvalues}, -${$dbhash->{data}{$time}{$direction}{total}{'total'}}[0+$reporttype]/$div;
                              } else {
                                   push @{$totalvalues}, ${$dbhash->{data}{$time}{$direction}{total}{'total'}}[1+$reporttype]/$div;
                              }
                         } else {
                              push @{$totalvalues},0;
                         }     
                    }
                    unshift @{$graphdata},$totalvalues;
                    unshift @{$graphtype},'lines';
                    if (param('predefinedcolors')) {
                         unshift @{$graphcolor}, $definedcolors->{'total'};
                    } else {
                         unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                    }
                    if ($which eq 'out') {
                         unshift @{$graphlegend}, "Total ".$direction;
                    } else {
                         unshift @{$graphlegend}, undef;
                    }
               }
          }
          if (param('tuples_stacked')) {
               my $tuplevaluesaccumulated=[];
               foreach my $direction (sort keys %{$subdir{tuples}} ) {
                    foreach my $tuple (sort keys %{$subdir{tuples}{$direction}}) {
                         my $tuplevalues=[];
                         my $i=0;
                         foreach my $time (@times) {
                              if (defined ${$dbhash->{data}{$time}{$direction}{tuples}{$tuple}}[0+$reporttype]) {
                                   if ($which eq 'in') {
                                        $tuplevaluesaccumulated->[$i] -= ${$dbhash->{data}{$time}{$direction}{tuples}{$tuple}}[0+$reporttype]/$div;
                                   } else {
                                        $tuplevaluesaccumulated->[$i] += ${$dbhash->{data}{$time}{$direction}{tuples}{$tuple}}[1+$reporttype]/$div;
                                   }
                              } else {
                                   $tuplevaluesaccumulated->[$i] += 0;
                              }
                              $i++;
                         }
                         push @{$tuplevalues},@{$tuplevaluesaccumulated};
                         unshift @{$graphdata},$tuplevalues;
                         unshift @{$graphtype},'area';
                         unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                         unshift @{$graphlegend}, "Tuple ".$tuple." ".$direction;
                    }
               }
          } else {
               foreach my $direction (sort keys %{$subdir{tuples}} ) {
                    foreach my $tuple (sort keys %{$subdir{tuples}{$direction}}) {
                         my $tuplevalues=[];
                         foreach my $time (@times) {
                              if (defined ${$dbhash->{data}{$time}{$direction}{tuples}{$tuple}}[0+$reporttype]) {
                                   if ($which eq 'in') {
                                        push @{$tuplevalues}, -${$dbhash->{data}{$time}{$direction}{tuples}{$tuple}}[0+$reporttype]/$div;
                                   } else {
                                        push @{$tuplevalues}, ${$dbhash->{data}{$time}{$direction}{tuples}{$tuple}}[1+$reporttype]/$div;
                                   }
                              } else {
                                   push @{$tuplevalues},0;
                              }
                         }
                         unshift @{$graphdata},$tuplevalues;
                         unshift @{$graphtype},'lines';
                         unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                         unshift @{$graphlegend}, "Tuple ".$tuple." ".$direction;
                    }
               }
          }
          if (param('service_stacked')) {
               my $servicevaluesaccumulated=[];
               foreach my $direction (sort keys %{$subdir{service}} ) {
                    foreach my $service (sort keys %{$subdir{service}{$direction}}) {
                         my $servicevalues=[];
                         my $i=0;
                         foreach my $time (@times) {
                              if (defined $dbhash->{data}{$time}{$direction}{service}{$service}) {
                                   if ($which eq 'in') {
                                        $servicevaluesaccumulated->[$i] -= ${$dbhash->{data}{$time}{$direction}{service}{$service}}[0+$reporttype]/$div;
                                   } else {
                                        $servicevaluesaccumulated->[$i] += ${$dbhash->{data}{$time}{$direction}{service}{$service}}[1+$reporttype]/$div;
                                   }
                              } else {
                                   $servicevaluesaccumulated->[$i] += 0;
                              }
                              $i++;
                         }
                         push @{$servicevalues},@{$servicevaluesaccumulated};
                         unshift @{$graphdata},$servicevalues;
                         unshift @{$graphtype},'area';
                         if (param('predefinedcolors')) {
                              unshift @{$graphcolor}, $definedcolors->{$service};
                         } else {
                              unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                         }
                         if ($which eq 'out') {
                              unshift @{$graphlegend}, "Service ".$service." ".$direction;
                         } else {
                              unshift @{$graphlegend}, undef;
                         }
                    }
               }
          } else {
               foreach my $direction (sort keys %{$subdir{service}} ) {
                    foreach my $service (sort keys %{$subdir{service}{$direction}}) {
                         my $servicevalues=[];
                         foreach my $time (@times) {
                              if (defined $dbhash->{data}{$time}{$direction}{service}{$service}) {
                                   if ($which eq 'in') {
                                        push @{$servicevalues}, -${$dbhash->{data}{$time}{$direction}{service}{$service}}[0+$reporttype]/$div;
                                   } else {
                                        push @{$servicevalues}, ${$dbhash->{data}{$time}{$direction}{service}{$service}}[1+$reporttype]/$div;
                                   }
                              } else {
                                   push @{$servicevalues},0;
                              }
                         }
                         unshift @{$graphdata},$servicevalues;
                         unshift @{$graphtype},'lines';
                         if (param('predefinedcolors')) {
                              unshift @{$graphcolor}, $definedcolors->{$service};
                         } else {
                              unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                         }
                         if ($which eq 'out') {
                              unshift @{$graphlegend}, "Service ".$service." ".$direction;
                         } else {
                              unshift @{$graphlegend}, undef;
                         }
                    }
               }
          }
          if (param('tos_stacked')) {
               my $tosvaluesaccumulated=[];
               foreach my $direction (sort keys %{$subdir{tos}} ) {
                    foreach my $tos (sort keys %{$subdir{tos}{$direction}}) {
                         my $tosvalues=[];
                         my $i=0;
                         foreach my $time (@times) {
                              if (defined ${$dbhash->{data}{$time}{$direction}{tos}{$tos}}[0+$reporttype]) {
                                   if ($which eq 'in') {
                                        $tosvaluesaccumulated->[$i] -= ${$dbhash->{data}{$time}{$direction}{tos}{$tos}}[0+$reporttype]/$div;
                                   } else {
                                        $tosvaluesaccumulated->[$i] += ${$dbhash->{data}{$time}{$direction}{tos}{$tos}}[1+$reporttype]/$div;
                                   }
                              } else {
                                   $tosvaluesaccumulated->[$i] += 0;
                              }
                              $i++;
                         }
                         push @{$tosvalues},@{$tosvaluesaccumulated};
                         unshift @{$graphdata},$tosvalues;
                         unshift @{$graphtype},'area';
                         if (param('predefinedcolors')) {
                              unshift @{$graphcolor}, $definedcolors->{$tos};
                         } else {
                              unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                         }
                         if ($which eq 'out') {
                              unshift @{$graphlegend}, "Tos ".$tos." ".$direction;
                         } else {
                              unshift @{$graphlegend}, undef;
                         }
                    }
               }
          } else {
               foreach my $direction (sort keys %{$subdir{tos}} ) {
                    foreach my $tos (sort keys %{$subdir{tos}{$direction}}) {
                         my $tosvalues=[];
                         foreach my $time (@times) {
                              if (defined ${$dbhash->{data}{$time}{$direction}{tos}{$tos}}[0+$reporttype]) {
                                   if ($which eq 'in') {
                                        push @{$tosvalues}, -${$dbhash->{data}{$time}{$direction}{tos}{$tos}}[0+$reporttype]/$div;
                                   } else {
                                        push @{$tosvalues}, ${$dbhash->{data}{$time}{$direction}{tos}{$tos}}[1+$reporttype]/$div;
                                   }
                              } else {
                                   push @{$tosvalues},0;
                              }
                         }
                         unshift @{$graphdata},$tosvalues;
                         unshift @{$graphtype},'lines';
                         if (param('predefinedcolors')) {
                              unshift @{$graphcolor}, $definedcolors->{$tos};
                         } else {
                              unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                         }
                         if ($which eq 'out') {
                              unshift @{$graphlegend}, "Tos ".$tos." ".$direction;
                         } else {
                              unshift @{$graphlegend}, undef;
                         }
                    }
               }
          }
          if (param('protocol_stacked')) {
               my $protocolvaluesaccumulated=[];
               foreach my $direction (sort keys %{$subdir{protocol}} ) {
                    foreach my $protocol (sort keys %{$subdir{protocol}{$direction}}) {
                         my $protocolvalues=[];
                         my $i=0;
                         foreach my $time (@times) {
                              if (defined $dbhash->{data}{$time}{$direction}{protocol}{$protocol}) {
                                   if ($which eq 'in') {
                                        $protocolvaluesaccumulated->[$i] -= ${$dbhash->{data}{$time}{$direction}{protocol}{$protocol}}[0+$reporttype]/$div;
                                   } else {
                                        $protocolvaluesaccumulated->[$i] += ${$dbhash->{data}{$time}{$direction}{protocol}{$protocol}}[1+$reporttype]/$div;
                                   }
                              } else {
                                   $protocolvaluesaccumulated->[$i] += 0;
                              }
                              $i++;
                         }
                         push @{$protocolvalues},@{$protocolvaluesaccumulated};
                         unshift @{$graphdata},$protocolvalues;
                         unshift @{$graphtype},'area';
                         if (param('predefinedcolors')) {
                              unshift @{$graphcolor}, $definedcolors->{$protocol};
                         } else {
                              unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                         }
                         if ($which eq 'out') {
                              unshift @{$graphlegend}, "Protocol ".$protocol." ".$direction;
                         } else {
                              unshift @{$graphlegend}, undef;
                         }
                    }
               }
          } else {
               foreach my $direction (sort keys %{$subdir{protocol}} ) {
                    foreach my $protocol (sort keys %{$subdir{protocol}{$direction}}) {
                         my $protocolvalues=[];
                         foreach my $time (@times) {
                              if (defined $dbhash->{data}{$time}{$direction}{protocol}{$protocol}) {
                                   if ($which eq 'in') {
                                        push @{$protocolvalues}, -${$dbhash->{data}{$time}{$direction}{protocol}{$protocol}}[0+$reporttype]/$div;
                                   } else {
                                        push @{$protocolvalues}, ${$dbhash->{data}{$time}{$direction}{protocol}{$protocol}}[1+$reporttype]/$div;
                                   }
                              } else {
                                   push @{$protocolvalues},0;
                              }
                         }
                         unshift @{$graphdata},$protocolvalues;
                         unshift @{$graphtype},'lines';
                         if (param('predefinedcolors')) {
                              unshift @{$graphcolor}, $definedcolors->{$protocol};
                         } else {
                              unshift @{$graphcolor}, $randomcolors->[int(rand 24)];
                         }
                         if ($which eq 'out') {
                              unshift @{$graphlegend}, "Protocol ".$protocol." ".$direction;
                         } else {
                              unshift @{$graphlegend}, undef;
                         }
                    }
               }
          }
     }
     
     foreach my $time ( @times ) {
          push @timestrings, scalar(localtime($time));
     }
     unshift @{$graphdata}, \@timestrings;
     
     my $graph = GD::Graph::mixed->new($width,$height);
     $graph->set( two_axes => 1,
                  zero_axis => 1,
                  transparent => 0,
                  types => $graphtype,
                  line_width => 2
     );
     $graph->set( dclrs => $graphcolor,
                  x_label_skip => $#times/6,
                  values_vertical => 1  );
     $graph->set_legend(@{$graphlegend});
     
     #use Data::Dumper;
     #print STDOUT $query->header();
     #foreach my $time ( sort keys %{$dbhash->{data}} ) {
     #    print STDOUT "Time:".$time."\n";
     #    print STDOUT Dumper($subdir)."\n";
     #}
     binmode STDOUT;     
     print STDOUT $query->header(-type => 'image/png');
     my $gd = $graph->plot($graphdata);
     print STDOUT $gd->png;
}
