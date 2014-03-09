#!/usr/bin/perl 

use qtc::msg; 
use Data::Dumper; 

sub dprint {
	return; 
	print @_; 
}
#print "hi\n"; 
my $msg=qtc::msg->new(call=>"oe1src", type=>"msg"); 

dprint "have obj set date \n"; 
$msg->msg_date($msg->rcvd_date); 
dprint "serial \n"; 
$msg->msg_serial(1); 
dprint "from \n"; 
$msg->from("oe1xgb"); 
dprint "to \n"; 
$msg->to("dd5tt"); 
dprint "msg \n"; 
$msg->msg("hallo zusammen, das ist eine testnachricht."); 

dprint "here we are \n \n";
dprint Dumper($msg);  
print $msg->as_xml; 

