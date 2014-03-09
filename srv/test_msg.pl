#!/usr/bin/perl 

use qtc::msg; 

my $msg=qtc::msg->new(call=>"OE1SRC", type=>"msg"); 

$msg->msg_date($msg->rcvd_date); 
$msg->msg_serial(1); 
$msg->from("OE1XGB"); 
$msg->to("DD5TT"); 
$msg->msg("hallo zusammen, das ist eine testnachricht."); 

print $msg->as_xml; 

