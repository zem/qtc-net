#!/usr/bin/perl 

use qtc::msg; 
use Data::Dumper; 

sub dprint {
	return; 
	print @_; 
}
#print "hi\n"; 
my $msg=qtc::msg->new(call=>"oe1src", type=>"telegram"); 

dprint "have obj set date \n"; 
$msg->telegram_date($msg->rcvd_date); 
dprint "from \n"; 
$msg->from("oe1xgb"); 
dprint "to \n"; 
$msg->to("dd5tt"); 
dprint "msg \n"; 
$msg->msg("hallo zusammen, das ist eine testnachricht."); 

dprint "here we are \n \n";
dprint Dumper($msg);  

print $msg->to_filesystem("."); 

