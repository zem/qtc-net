package qtc::WebApp::QuickInterface; 

##################################################################
# pleae note and use (param("foo"))[0] whenever you need only one 
# url Parameter to prevent URL injections
################################################################# 

use base 'qtc::WebApp'; 

########################################################
# Put some layout around the form. You may change this 
# when you inherit this class for your application
#######################################################
sub cgiapp_postrun {
	my $obj=shift; 
	my $out_ref=shift;
	
	$$out_ref="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<qtc>\n".$$out_ref."</qtc>"; 
}

sub setup {
	my $obj = shift;
	$obj->SUPER::setup(); 
	$obj->header_add( -type => 'application/xml' );
	
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
	if ( ! ($q->param("type"))[0] ) { $q->param("type", "new"); }
	my $type=($q->param("type"))[0];
	if ( $type !~ /^((all)|(new)|(sent)|(timeline)|(timeline_new))$/ ) { return "<error>unknown search type</error>"; }
	my $r; 

	if ( ( $obj->logged_in ) and ( ! ($q->param("call"))[0] ) ) {
		$q->param("call", $q->param("publisher_call"));
	}

	if ( ! ($q->param("call"))[0] ) { 
		return '<error>I need a call to do any work</error>'; 
	}

	#prepare qsp checksum hash
	my %qsp; 
	foreach $chk ($q->param("qsp")) { $qsp{$chk}=1; }

	my @msgs=$obj->qtc_query->list_telegrams(($q->param("call"))[0], $type);
	my @rows; 
	foreach my $msg (@msgs) {  
		if ( ( $qsp{$msg->checksum} ) and ($obj->logged_in) and (($q->param("call"))[0]) ) {
			$obj->qtc_publish->qsp(
				msg=>$msg,
				to=>($q->param("call"))[0],
			);
			$r.="<qsp>\n";
			$r.="	<telegram_checksum>".$msg->checksum."</telegram_checksum>\n";
			$r.="	<to>".($q->param("call"))[0]."</to>\n";
			$r.="</qsp>\n";
			next; 
		} 
		$r.="<telegram>\n";
		$r.="	<checksum>".$msg->checksum."</checksum>\n";
		$r.="	<signature>".$msg->signature."</signature>\n";
		$r.="	<signature_key_id>".$msg->signature_key_id."</signature_key_id>\n";
		$r.="	<call>".$msg->call."</call>\n";
		$r.="	<hr_refnum>".$msg->hr_refnum."</hr_refnum>\n";
		$r.="	<from>".$msg->from."</from>\n";
		$r.="	<to>".$msg->to."</to>\n";
		$r.="	<telegram_date>".$msg->telegram_date."</telegram_date>\n";
		$r.="	<telegram>".$msg->telegram."</telegram>\n";
		$r.="</telegram>\n"; 
	} 	
	return $r; 
}

sub mode_send_telegram {
	my $o=shift; 
	my $r; 
	if ( ! $o->logged_in ) {
		$r.="<error>Please log in to use this feature</error>"; 
		return $r; 
	}
	if ( ($o->q->param("telegram"))[0] )  {
		# convert characters 
		$o->q->param("call", $o->qtc_query->allowed_letters_for_call(($o->q->param("call"))[0]));
		$o->q->param("to", $o->qtc_query->allowed_letters_for_call(($o->q->param("to"))[0]));
		$o->q->param("telegram", $o->qtc_query->allowed_letters_for_telegram(($o->q->param("telegram"))[0]));
	
		my $ok=1; 
		if (! ($o->q->param("call"))[0] ) { 
			$r.="<error>Please enter a valid callsign </error>";
			$ok=0; 
		}
		if (! ($o->q->param("to"))[0] ) { 
			$r.="<error>Please enter a valid telegram receiver callsign</error>";
			$ok=0; 
		}
		if (! ($o->q->param("telegram"))[0] ) { 
			$r.="<error>Please enter a valid telegram text</error>";
			$ok=0; 
		}
		if ( $ok ) { 
			$o->qtc_publish->telegram(
				call=>($o->q->param("publisher_call"))[0],
				from=>($o->q->param("call"))[0],
				to=>($o->q->param("to"))[0],
				telegram=>($o->q->param("telegram"))[0],
			); 
			$r.="<sent_telegram>\n";
			$r.="	<call>".($o->q->param("publisher_call"))[0]."</call>\n"; 
			$r.="	<from>".($o->q->param("call"))[0]."</from>\n"; 
			$r.="	<to>".($o->q->param("to"))[0]."</to>\n"; 
			$r.="	<telegram>".($o->q->param("telegram"))[0]."</telegram>\n"; 
			$r.="</sent_telegram>\n";
			$o->q->param("mode", "show_telegrams"); 
			return $r.$o->mode_show_telegrams; 
		} 
	}

	return "<error>You should provide call from to and telegram + loogin credentials</error>";
}

1;
