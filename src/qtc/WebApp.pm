package qtc::WebApp; 

use base 'CGI::Application'; 
use qtc::query; 
use qtc::publish; 

sub setup {
	my $obj = shift;
	$obj->start_mode('ask_call');
	$obj->mode_param('mode');
	$obj->run_modes(
		'ask_call' => 'mode_ask_call',
	);
	if ( ! $obj->{qtc}->{path} ) { $obj->{qtc}->{path}=$ENV{HOME}."/.qtc"; }
	if ( ! $obj->{qtc}->{query} ) { $obj->{qtc}->{query}=qtc::query->new(path=>$obj->{qtc}->{path}); }

}
sub qtc_query { my $obj; return $obj->{qtc}->{query}; }

sub mode_ask_call {
	my $obj=shift; 

}

sub mode_show_messages {
	my $obj=shift; 
	my $q=$obj->query;
	if ( ! $q->param("type") ) { $q->param("type", "new"); }
	my $type=$q->param("type");
	if ( $type !~ /^((all)|(new)|(sent))$/ ) { return "<h1>FAIL telegram type invalid</h1>"; }
	if ( ! $q->param("call") ) { return "<h1>I don't have a call</h1>"; }

	my @msgs=$obj->qtc_query->list_telegrams($call, $type);
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
