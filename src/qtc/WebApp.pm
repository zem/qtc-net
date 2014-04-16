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

sub html_input_hidden {
	my $obj=shift; 
	my $r; 
	foreach my $p (keys %{$obj->{qtc}->{exports}}) {
		$r.=$obj->html_e("input", {
				type=>"hidden", 
				name=>$p,
				value=>$obj->q->param($p),
			}
		); 
	}
	return $r; 
}

sub html_form {
	my $obj=shift; 
	my @r=@_; 
	my $x=$obj->html_e("form", {
		action=>$obj->q->url(-full=>1),
		method=>"POST",
		}, 
		$obj->html_input_hidden,
		@r,
	); 
	return $x; 
}

sub html_e {
	my $obj=shift; 
	my $name=shift; 
	my $p=shift; 
	my @r=@_; 
	
	print "<$name "; 
	foreach my $key (keys %$p) { print "$key=\"".$obj->q->escapeHTML($$p{$key})."\" "; }
	print ">"; 
	print join("", @r);
	print "</$name>";  
}

sub html_table {
	my $obj=shift;
	return $obj->html_e("table", @_); 
}

sub html_h1 {
	my $obj=shift;
	return $obj->html_e("h1", @_); 
}

sub mode_ask_call {
	my $obj=shift; 
	my $r;

	$r.=$obj->html_form(
		'<input type="text" size="10" maxlength="20" name="call"/>',
		'<input type="submit" name="QTC?"/>',
	); 

	return $r; 
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
