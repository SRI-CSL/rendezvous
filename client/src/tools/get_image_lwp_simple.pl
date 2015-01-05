#!/usr/bin/perl
use strict;
use File::Temp qw/ tempfile /;
require LWP::UserAgent;
use MIME::Base64;

if(@ARGV != 2){
    print "Usage: ${0} <server> <imagefile>\n";
    exit;
} else {
    my $server = $ARGV[0];
    my $request_cmd = "./generate_request ${server}";
    my $request = qx|${request_cmd}|;
    
    die "Couldn't generate a request! Try executing this on the command line:\n\t${request_cmd}\n" unless $request;

    my ($password, $url) = split /\n/, $request;
  
    print "Password: ${password}\n";

    my $filename = $ARGV[1];

    unless($filename =~ m|.jpg$|){
        print "WARNING: outguess is fussy about the EXTENSIONS of filenames -- fixing ...\n";
        $filename = "${filename}.jpg";
    }

    my $fh;

    open( $fh, '>', $filename) or die "Couldn't open ${filename} for writing $!";
    
    my %options = (     );
    
    my $agent =  LWP::UserAgent->new( %options );
    
    my $request = HTTP::Request->new(GET => $url);
    
    my $response = $agent->request($request);
    
    my $headers = $response->headers_as_string;

    print "Request: " . $request->as_string . "\n";
    
    print "Response Code: " .  $response->code . "\n";

    print $headers;

    print $fh $response->content;

    close($fh);

    #bit of a hack: raw onion == 'image/gif'  stegged onion == 'image/jpeg'
    if($headers =~ m|Content-Type: image/jpeg|){
        #stegged onion
        my  ($onionfh, $onionfile) = tempfile( 'onionXXXXX', DIR => '.');
        my $extract = "outguess -k ${password} -r ${filename} ${onionfile}";
        print "${extract}\n";
        my $extraction = `${extract}`;
        my $verification = `./validate_onion ${onionfile} ${password}`;
        print $verification;
    } elsif($headers =~ m|Content-Type: image/gif|) {
        #raw onion
        my $verification = `./validate_onion ${filename} ${password}`;
        print $verification;
    } else {
        print "Wasn't expecting a format such as this\n";
    }

}
