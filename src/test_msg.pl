#!/usr/bin/perl 

use qtc::interface::http; 

my $if=qtc::interface::http->new(url=>"http://localhost/qtc-if.cgi", use_digest=>1); 
$if->sync("/out"); 


