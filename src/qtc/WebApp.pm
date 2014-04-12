package qtc::WebApp; 

use base 'CGI::Application'; 

sub setup {
	my $obj = shift;
	$obj->start_mode('ask_call');
	$obj->mode_param('mode');
	$obj->run_modes(
		'ask_call' => 'mode_ask_call',
	);
}

sub mode_ask_call {
	my $obj=shift; 

}

########################################################
# Put some layout around the form. You may change this 
# when you inherit this class for your application
#######################################################
sub cgiapp_postrun {
	my $obj=shift; 
	my $out_ref=shift;
	my $cgi = $obj->query(); 
	my $out=$cgi->start_html(
		-title=>"QTC Network Web Access",
	); 

	$out.=$$out_ref; 

	$out.=$cgi->end_html; 
	
	# return output.... 
	$$out_ref=$out; 
}


1;
