#!/usr/bin/perl 

use qtc::msg; 
use Data::Dumper; 

print "hi\n"; 
my $msg=qtc::msg->new(call=>"OE1SRC", type=>"msg"); 

print "have obj set date \n"; 
$msg->msg_date($msg->rcvd_date); 
print "serial \n"; 
$msg->msg_serial(1); 
print "from \n"; 
$msg->from("OE1XGB"); 
print "to \n"; 
$msg->to("DD5TT"); 
print "msg \n"; 
$msg->msg(uc("hallo zusammen, das ist eine testnachricht.")); 

print "here we are \n \n";
print Dumper($msg);  
print $msg->as_xml; 

