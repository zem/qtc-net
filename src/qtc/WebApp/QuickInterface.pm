package qtc::WebApp::QuickInterface; 
use base 'qtc::WebApp'; 

########################################################
# Put some layout around the form. You may change this 
# when you inherit this class for your application
#######################################################
sub cgiapp_postrun {
	my $obj=shift; 
	my $out_ref=shift;
	
	# THINK ABOUT ENCAPSULATING OUT REF	
}

sub setup {
	my $obj = shift;
	$obj->SUPER::setup(); 
	
	$obj->run_modes(
		'show_telegrams' => 'mode_show_telegrams',
		'send_telegram' => 'mode_send_telegram',
	);
}



###############################################################
# webapp modes 
##############################################################
sub mode_show_telegrams {
	my $obj=shift; 
	my $q=$obj->query;
	if ( ! $q->param("type") ) { $q->param("type", "new"); }
	my $type=$q->param("type");
	if ( $type !~ /^((all)|(new)|(sent))$/ ) { return "<h1>FAIL telegram type invalid</h1>"; }
	my $r; 

	if ( ( $obj->logged_in ) and ( ! $q->param("call") ) ) {
		$q->param("call", $q->param("publisher_call"));
		#$r.="<h3>You may search for telegrams to other calls in the upper left, I display the telegrams to YOUR publisher call until then</h3>"; 
	}

	$r.=$obj->area_navigation; 

	if ( ! $q->param("call") ) { 
		$r.="<h3>Please enter a call in the upper left corner or login in the upper right one.</h3>";
		$r.='<p></p>
<p>QTC Net is a decentralized telegram system for amateur radio. A user can check in a telegram 
from any sender to any receiver, as well as access those telegrams and mark them as delivered when 
they are delivered.</p>';
		$r.='<p>you may browse to 
<a href="'.$obj->{qtc}->{home_page}.'">'.$obj->{qtc}->{home_page}.'</a> if you want more information</p>';
		return $r; 
 
	}

	#prepare qsp checksum hash
	my %qsp; 
	foreach $chk ($q->param("qsp")) { $qsp{$chk}=1; }

	$r.="<h3>$type qtc telegrams for ".$q->param("call").":</h3>";
	my @msgs=$obj->qtc_query->list_telegrams($q->param("call"), $type);
	my @rows; 
	foreach my $msg (@msgs) {  
		if ( ( $qsp{$msg->checksum} ) and ($obj->logged_in) and ($q->param("call")) ) {
			$obj->qtc_publish->qsp(
				msg=>$msg,
				to=>$q->param("call"),
			);
			next; 
		} 
		push @rows, $obj->h_tr({},
			$obj->h_td({}, $obj->format_msg_in_html($msg)),
			$obj->filter_login_required(
				$obj->h_td({}, $obj->h_e("input", {type=>"checkbox", name=>"qsp", value=>$msg->checksum})),
			), 
		); 
	} 	

	$r.=$obj->h_e("center",{}, $obj->h_form({}, 
		$obj->h_table({}, 
			@rows,
			$obj->h_tr({},
				$obj->h_td({}), 
				$obj->filter_login_required(
					$obj->h_td({}, $obj->h_e("input", {
						type=>"submit", 
						name=>"submit", 
						value=>"QSP",
						onClick=>$obj->js_confirm("Have you really forwarded the checked messages to $call?"),
					})),
				), 
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


sub mode_send_telegram {
	my $o=shift; 
	my $r; 
	$r.=$o->area_navigation; 

	if ( ! $o->logged_in ) {
		$r.="<h3>Please log in to use this feature</h3>"; 
		return $r; 
	}
	if ( ( $o->q->param("submit") ) and ( $o->q->param("telegram") ) )  {
		# convert characters 
		$o->q->param("call", $o->qtc_query->allowed_letters_for_call($o->q->param("call")));
		$o->q->param("to", $o->qtc_query->allowed_letters_for_call($o->q->param("to")));
		$o->q->param("telegram", $o->qtc_query->allowed_letters_for_telegram($o->q->param("telegram")));
	
		my $ok=1; 
		if (! $o->q->param("call")) { 
			$r.="<h4>ERROR: Please enter a valid callsign </h4>";
			$ok=0; 
		}
		if (! $o->q->param("to")) { 
			$r.="<h4>ERROR: Please enter a valid telegram receiver callsign </h4>";
			$ok=0; 
		}
		if (! $o->q->param("telegram")) { 
			$r.="<h4>ERROR: Please enter a valid telegram text</h4>";
			$ok=0; 
		}
		if ( $ok ) { 
			$o->qtc_publish->telegram(
				call=>$o->q->param("publisher_call"),
				from=>$o->q->param("call"),
				to=>$o->q->param("to"),
				telegram=>$o->q->param("telegram"),
			); 
			$o->q->param("mode", "show_telegrams"); 
			return $o->mode_show_telegrams; 
		} 
	}

	delete $o->{qtc}->{exports}->{call}; 
	$r.="<center>";
	$r.=$o->h_tabled_form({},
		$o->h_labled_input({
			label=>"From:", 
			type=>"text", 
			size=>10, 
			maxlength=>20, 
			name=>"call",
			value=>$o->q->param("call"), 
		}),
		$o->h_labled_input({
			label=>"To:", 
			type=>"text", 
			size=>10, 
			maxlength=>20, 
			name=>"to",
			value=>$o->q->param("to"), 
		}),
		$o->h_labled_input({
			label=>"Telegram:", 
			type=>"text", 
			size=>100, 
			maxlength=>300, 
			name=>"telegram",
			value=>$o->q->param("telegram"), 
		}),
		$o->h_submit_for_tbl({
			onClick=>$o->js_confirm("Do you really want to send this Telegram?"),
			value=>"send telegram",
		}), 
	);
	$r.="</center>";
	$o->{qtc}->{exports}->{call}=1; 

	$r.="<p>Note: telegrams can be 300 small letter characters as well as numbers and some 
	signs, the telegrams are automatically converted to a storeable format. 
	This means lowercase convertion and every unknown character will vanish. </p>"; 
	
	return $r;
}




1;
