#!/usr/bin/perl
use strict;
use File::Temp qw/ tempfile /;

use constant DEBUG => 1;

if((@ARGV != 3) && (@ARGV != 4) && (@ARGV != 5)){
    print "Usage: ${0} <defiant public key> <server> <imagefile> [<port> [<sockshost:socksport>]]\n";
    exit;
} else {
    my $public_key =  $ARGV[0];
    my $server = $ARGV[1];
    my $serverport = (@ARGV < 4) ? 80 : int $ARGV[3];
    my $request_cmd = "./generate_request ${server} ${serverport}";
    my $request = qx|${request_cmd}|;
    my $socks;
    if(@ARGV == 5){ 
        $socks =  $ARGV[4]; 
        print "Using proxy at: ${socks}\n";
    }
    die "Couldn't generate a request! Try executing this on the command line:\n\t${request_cmd}\n" unless $request;

    my ($password, $url) = split /\n/, $request;
    print "Password: ${password}\n";
    if(DEBUG){ print "URI: ${url}\n"; }

    my $filename = $ARGV[2];

    unless($filename =~ m|.jpg$|){
        print "WARNING: outguess is fussy about the EXTENSIONS of filenames -- fixing ...\n";
        $filename = "${filename}.jpg";
    }


    my $fh;
    open( $fh, '>', $filename) or die "Couldn't open ${filename} for writing $!";
    close(  $fh  );

    my $curl_cmd = "curl ";
    if($serverport == 443){
        $curl_cmd .= "--insecure ";
    }

    if($socks){
        $curl_cmd .= " --socks4 ${socks} ";
    }
    
    my  ($headersfh, $headersfile) = tempfile( 'headersXXXXX', DIR => '.');

    $curl_cmd .= " --output ${filename} --dump-header ${headersfile} \"${url}\"";

    if(DEBUG){ print "curl_cmd = ${curl_cmd}\n"; }

    my $curl_request = qx|${curl_cmd}|;

    if(DEBUG){ print "curl_request = ${curl_request}\n"; }

    
    local $/;
    
    my $headers = <$headersfh>;
    
    if(DEBUG){ print "headers= ${headers}\n"; }
    
    
    #bit of a hack: raw onion == 'image/gif'  stegged onion == 'image/jpeg'
    if($headers =~ m|Content-Type: image/jpeg|){
        #stegged onion
        my  ($onionfh, $onionfile) = tempfile( 'onionXXXXX', DIR => '.');
        #unwedge -outfile target image
        my $extract = "unwedge -outfile ${onionfile} ${filename}";
        print "${extract}\n";
        my $extraction = `${extract}`;


        my $verifier = "./validate_onion  ${public_key}  ${onionfile} ${password}";
        print $verifier;
        my $verification = `${verifier}`;
        print $verification;
        close($onionfh);
        unlink($onionfile);
    } elsif($headers =~ m|Content-Type: image/gif|) {
        #raw onion
        my $verification = `./validate_onion ${public_key} ${filename} ${password}`;
        print $verification;
    } else {
        print "Wasn't expecting a format such as this\n";
    }
    
    close($headersfh);
    unlink $headersfile;
    
    print "OK\n";
}
