#!/usr/bin/perl 

use qtc::interface::http; 

if ( $#ARGV == -1 ) { print "Usage: $0 url [url2] ...\n"; exit; }

# url may be http://localhost/qtc_if.cgi
foreach my $url (@ARGV) {
	my $if=qtc::interface::http->new(url=>$url); 
	$if->sync("/in"); 
}

