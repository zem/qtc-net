package qtc::WebApp; 

use base 'CGI::Application'; 
use qtc::query; 
use qtc::publish; 
use Data::Dumper; 
use POSIX qw(strftime); 

# options are to be processed here 
sub cgiapp_init {
	my $obj=shift; 
	my %args=@_;
	if ( $args{qtc} ) { $obj->{qtc}=$args{qtc}; }
}

sub setup {
	my $obj = shift;
	$obj->start_mode('show_messages');
	$obj->mode_param('mode');
	$obj->run_modes(
		'show_messages' => 'mode_show_messages',
	);
	if ( ! $obj->{qtc}->{path} ) { $obj->{qtc}->{path}=$ENV{HOME}."/.qtc"; }
	if ( ! $obj->{qtc}->{query} ) { $obj->{qtc}->{query}=qtc::query->new(path=>$obj->{qtc}->{path}); }
	$obj->{qtc}->{exports}->{mode}=1;
	$obj->{qtc}->{exports}->{call}=1;
	$obj->{qtc}->{exports}->{type}=1;
	$obj->{qtc}->{exports}->{publisher_call}=1;
	$obj->{qtc}->{exports}->{publisher_password}=1;

}
sub qtc_query { my $obj=shift; return $obj->{qtc}->{query}; }
sub q { my $obj=shift; return $obj->query; }

sub h_input_hidden {
	my $obj=shift; 
	my $r; 
	foreach my $p (keys %{$obj->{qtc}->{exports}}) {
		if ( ! $obj->q->param($p) ) { next; }
		$r.=$obj->h_e("input", {
				type=>"hidden", 
				name=>$p,
				value=>$obj->q->param($p),
			}
		); 
	}
	return $r; 
}

sub h_tabled_form {
	my $obj=shift; 
	my $p=shift; 
	my @r=@_; 

	return $obj->h_form($p, 
		$obj->h_table({}, 
			@r
		),
	); 
}

sub h_form {
	my $obj=shift;
	my $p=shift; 
	my @r=@_; 
	my $x=$obj->h_e("form", {
		action=>$obj->q->url(-full=>1),
		method=>"POST",
		}, 
		$obj->h_input_hidden,
		@r,
	); 
	return $x; 
}

sub h_e {
	my $obj=shift; 
	my $name=shift; 
	my $p=shift; 
	my @r=@_; 
	my $x; 

	$x.="<$name "; 
	foreach my $key (keys %$p) { $x.="$key=\"".$obj->q->escapeHTML($$p{$key})."\" "; }
	$x.=">"; 
	$x.=join("", @r);
	$x.="</$name>"; 
	return $x; 
}

sub h_table {
	my $obj=shift;
	my $p=shift; 
	my @r=@_; 
	return $obj->h_e("table", $p, @r); 
}

sub h_td {
	my $obj=shift;
	my $p=shift; 
	return $obj->h_e("td", $p, @_); 
}

sub h_tr {
	my $obj=shift;
	my $p=shift; 
	return $obj->h_e("tr", $p, @_); 
}

sub h_h1 {
	my $obj=shift;
	my $p=shift; 
	return $obj->h_e("h1", $p, @_); 
}

# you need to be in a table to use this....
sub h_submit_for_tbl {
	my $obj=shift; 
	my $p=shift; 
	if ( ! $p->{type} ) { $p->{type}="submit"; }
	if ( ! $p->{name} ) { $p->{name}="submit"; }
	if ( ! $p->{value} ) { $p->{value}="Submit"; }
	my @r=@_; 
	return $obj->h_e("tr", {}, 
		$obj->h_e("td", {align=>"center", colspan=>2},
			$obj->h_e("input", $p),
		), 
	);
}
# you need to be in a table to use this....
sub h_labled_input {
	my $obj=shift; 
	my $p=shift; 
	my @r=@_; 
	my $label=$obj->q->escapeHTML($p->{label}); 
	delete $p->{label};

	return $obj->h_e("tr", {}, 
		$obj->h_e("td", {align=>"left"}, $label), 
		$obj->h_e("td", {align=>"right"},
			$obj->h_e("input", $p, $default),
		), 
	);
}

sub area_ask_call {
	my $obj=shift; 
	my $r;
	my $call=$obj->q->param("call");
	$call=$obj->qtc_query->allowed_letters_for_call($call); 
	if ( ! $call ) { 
		#$obj->q->delete("call");
	} else {
		$obj->q->param("call", $call);
	}
	delete $obj->{qtc}->{exports}->{call}; 
	$r.=$obj->h_tabled_form({}, 
		$obj->h_labled_input({
			label=>"Callsign:", 
			type=>"text", 
			size=>10, 
			maxlength=>20, 
			name=>"call",
			value=>$call, 
		}),
		$obj->h_submit_for_tbl({value=>"QTC?"}), 
	);
	$obj->{qtc}->{exports}->{call}=1; 

	return $r; 
}

sub area_user_pass {
	my $obj=shift; 
	my $r;
	my $publisher_call=$obj->q->param("publisher_call");
	$publisher_call=$obj->qtc_query->allowed_letters_for_call($publisher_call); 
	if ( ! $call ) { 
		$obj->q->delete("publisher_call");
	} else {
		$obj->q->param("publisher_call", $publisher_call);
	}

	delete $obj->{qtc}->{exports}->{publisher_call};
	delete $obj->{qtc}->{exports}->{publisher_password};

	$r.=$obj->h_tabled_form({}, 
		$obj->h_labled_input({
			label=>"YOUR Callsign:", 
			type=>"text", 
			size=>10, 
			maxlength=>20, 
			name=>"publisher_call",
			value=>$publisher_call, 
		}),
		$obj->h_labled_input({
			label=>"YOUR Password:", 
			type=>"password", 
			size=>10, 
			maxlength=>50, 
			name=>"publisher_password",
			value=>$publisher_password, 
		}),
		$obj->h_submit_for_tbl({value=>"publischer login"}), 
	);
	
	$obj->{qtc}->{exports}->{publisher_call}=1;
	$obj->{qtc}->{exports}->{publisher_password}=1;

	return $r; 
}

sub mode_show_messages {
	my $obj=shift; 
	my $q=$obj->query;
	if ( ! $q->param("type") ) { $q->param("type", "new"); }
	my $type=$q->param("type");
	if ( $type !~ /^((all)|(new)|(sent))$/ ) { return "<h1>FAIL telegram type invalid</h1>"; }
	my $r; 
	$r.="<table width=\"100%\"><td align=\"left\">".$obj->area_ask_call."</td>\n";
	$r.="<td align=\"right\">".$obj->area_user_pass."</td>\n";
	$r.="</table><hr/>";

	if ( ! $q->param("call") ) { return $r."<h3>Please enter a Call</h3>"; }

	$r.="<h3>$type qtc telegrams for ".$q->param("call").":</h3>";
	my @msgs=$obj->qtc_query->list_telegrams($q->param("call"), $type);
	my @rows; 
	foreach my $msg (@msgs) {  
		push @rows, $obj->h_tr({},
					$obj->h_td({}, $obj->format_msg_in_html($msg)),
					$obj->h_td({}, $obj->h_e("input", {type=>"checkbox", name=>"qsp", value=>$msg->checksum})),
		); 
	} 	

	$r.=$obj->h_e("center",{}, $obj->h_form({}, 
		$obj->h_table({}, 
			@rows,
			$obj->h_tr({},
				$obj->h_td({}), 
				$obj->h_td({}, $obj->h_e("input", {type=>"submit", name=>"submit", value=>"QSP"})), 
			),
		), 
	)); 
	$r.="<b>Show me: ";
	$r.="<table><tr>";
	$q->param("type", "new"); 
	$r.="<td>".$obj->h_form({},
		$obj->h_e("input", {type=>"submit", name=>"submit", value=>"new"}),
	)."</td>"; 
	$q->param("type", "all"); 
	$r.="<td>".$obj->h_form({},
		$obj->h_e("input", {type=>"submit", name=>"submit", value=>"all"}),
	)."</td>"; 
	$q->param("type", "sent"); 
	$r.="<td>".$obj->h_form({},
		$obj->h_e("input", {type=>"submit", name=>"submit", value=>"sent"}),
	)."</td>"; 
	$q->param("type", $type); 
	$r.="</tr></table>";
	$r.="</b>";
	return $r; 
}

sub format_msg_in_html {
	my $o=shift; 
	my $msg=shift; 
	my $r; 
	$r.=$o->h_table({}, 
		$o->h_tr({}, 
			$o->h_td({}, "<b>number:</b> ".$msg->hr_refnum),
			$o->h_td({colspan=>2}, "<b>publisher:</b> ".$msg->call),
		),
		$o->h_tr({}, 
			$o->h_td({}, "<b>from:</b> ".$msg->from),
			$o->h_td({}, "<b>to:</b> ".$msg->to),
			$o->h_td({}, "<b>date:</b> ".strftime("%Y-%m-%d %H:%M:%S UTC", gmtime($msg->telegram_date))),
		),
		$o->h_tr({}, 
			$o->h_td({colspan=>3}, "<b>telegram:</b> ".$msg->telegram),
		),
	);
	return $r; 
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

	$out.=$obj->h_e("center", {}, $obj->h_h1({}, "QTC Net Web Access")); 
	$out.=$obj->h_e("hr"); 
	$out.=$$out_ref; 

	$out.=$cgi->end_html; 
	
	# return output.... 
	$$out_ref=$out; 
}


1;
