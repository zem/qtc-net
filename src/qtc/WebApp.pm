package qtc::WebApp; 

use base 'CGI::Application'; 
use qtc::query; 
use qtc::publish; 
use Data::Dumper; 
use Digest::SHA qw(sha256_hex); 
use POSIX qw(strftime); 
use Authen::Captcha; # the Application Captcha plugin was not installable


###########################################################################
# Cgiapp control functions 
##########################################################################
# options are to be processed here 
sub cgiapp_init {
	my $obj=shift; 
	my %args=@_;
	if ( $args{qtc} ) { $obj->{qtc}=$args{qtc}; }
}

########################################################
# Put some layout around the form. You may change this 
# when you inherit this class for your application
#######################################################
sub cgiapp_postrun {
	my $obj=shift; 
	my $out_ref=shift;
	
	# we need this for the captcha_image mode that returns a jpeg
	if ( $obj->{disable_postrun} ) { return; }

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

sub setup {
	my $obj = shift;
	$obj->start_mode('show_messages');
	$obj->mode_param('mode');
	$obj->run_modes(
		'captcha_image' => 'mode_captcha_image',
		'show_messages' => 'mode_show_messages',
		'register_publisher_login' => 'mode_register_publisher_login',
		'save_publisher_login' => 'mode_save_publischer_login',
	);
	# CONFIGURE
	if ( ! $obj->{qtc}->{path} ) { $obj->{qtc}->{path}=$ENV{HOME}."/.qtc"; }
	# CONFIGURE
	if ( ! $obj->{qtc}->{priv_path_prefix} ) { $obj->{qtc}->{priv_path_prefix}=$ENV{HOME}."/.qtc_webapp_credentials"; }
	if ( ! $obj->{qtc}->{captcha_data_dir} ) { $obj->{qtc}->{captcha_data_dir}=$obj->{qtc}->{priv_path_prefix}."/captcha_data_dir"; }
	if ( ! $obj->{qtc}->{captcha_output_dir} ) { $obj->{qtc}->{captcha_output_dir}=$obj->{qtc}->{priv_path_prefix}."/captcha_output_dir"; }

	# objects ....
	if ( ! $obj->{qtc}->{query} ) { $obj->{qtc}->{query}=qtc::query->new(path=>$obj->{qtc}->{path}); }
	if ( ! $obj->{qtc}->{captcha} ) { 
		$obj->{qtc}->{captcha}=Authen::Captcha->new(
			data_folder=>$obj->{qtc}->{captcha_data_dir},
			output_folder=>$obj->{qtc}->{captcha_output_dir},
		); 
	}


	$obj->{qtc}->{exports}->{mode}=1;
	$obj->{qtc}->{exports}->{call}=1;
	$obj->{qtc}->{exports}->{type}=1;
	$obj->{qtc}->{exports}->{publisher_call}=1;
	$obj->{qtc}->{exports}->{publisher_password}=1;
	
	# the login data is required very very early so we need to check this during setup!
	my $publisher_call=$obj->q->param("publisher_call");
	$publisher_call=$obj->qtc_query->allowed_letters_for_call($publisher_call); 
	if ( ! $publisher_call ) { 
		$obj->q->delete("publisher_call");
	} else {
		$obj->q->param("publisher_call", $publisher_call);
	}

}

###############################################################
# object helpers
###############################################################
sub qtc_query { my $obj=shift; return $obj->{qtc}->{query}; }
sub qtc_publish { 
	my $o=shift; 
	if ( ! $o->{qtc}->{publish} ) { 
		if ( ! $o->logged_in ) { return; }
		$o->{qtc}->{publish}=qtc::publish->new(
			privpath=>$o->get_priv_dir, 
			call=>$o->q->param("publisher_call"),
			password=>$o->q->param("publisher_password"),
		); 
	}
	return $o->{qtc}->{publish};
}
sub q { my $obj=shift; return $obj->query; }

sub get_priv_dir {
	my $obj=shift; 
	my $user=$obj->q->param("publisher_call");
	my $pass=$obj->q->param("publisher_password");
	if ( ! $obj->{qtc}->{priv_dir} ) {
		my $user_pass_sha=$obj->qtc_query->call2fname($user)."_".sha256_hex($pass);
		$obj->{qtc}->{priv_dir}=$obj->{qtc}->{priv_path_prefix}."/".$user_pass_sha;
	}
	return $obj->{qtc}->{priv_dir}; 
}

sub filter_login_required {
	my $obj=shift; 
	if ( ! $obj->logged_in ) { return; }
	return @_; 
}

sub logged_in {
	my $obj=shift; 
	if ( 
		( $obj->q->param("publisher_call") )  and 
		( $obj->q->param("publisher_password") ) and
		( -d $obj->get_priv_dir )
	) { return 1; } 
	else 
	{ return 0; }
}

sub publisher_exists {
	my $o=shift; 
	my $user=$o->q->param("publisher_call");
	if ( ! $user ) { return; }
	my @scan=$o->qtc_query->scan_dir($o->{qtc}->{priv_path_prefix}, '^'.$o->qtc_query->call2fname($user).'_[a-f0-9]+$');
	if ( $#scan == -1 ) { return; }
	return 1; 
}

##################################################################
# HTML Generation (maybe not the best idea but there it is)
##################################################################
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
		$obj->h_e("td", {align=>"left"}, "<b>".$label."</b>"), 
		$obj->h_e("td", {align=>"right"},
			$obj->h_e("input", $p),
		), 
	);
}
# you need to be in a table to use this....
sub h_captcha {
	my $o=shift; 
	my $p=shift; 
	my @r=@_; 
	my $label=$o->q->escapeHTML($p->{label}); 
	delete $p->{label};
	if ( ! $label ) { $label="Captcha:"; }	

	# defaults
	if ( ! $p->{name} ) { $p->{name}="captcha"; }
	if ( ! $p->{type} ) { $p->{type}="text"; }
	if ( ! $p->{size} ) { $p->{size}=10; }
	if ( ! $p->{maxlength} ) { $p->{maxlength}=5; }

	my $x;
	$x.="<tr><td></td><td>";
	my $token=$o->{qtc}->{captcha}->generate_code(5);
	$x.="<input type=\"hidden\" name=\"captcha_token\" value=\"$token\"></input>"; 
	$x.="<img src=\"".$o->q->url(-full=>1)."?mode=captcha_image;token=".$token."\"></img>";
	$x.="</td><tr>";

	$x.=$o->h_e("tr", {}, 
		$o->h_e("td", {align=>"left"}, "<b>".$label."</b>"), 
		$o->h_e("td", {align=>"right"},
			$o->h_e("input", $p),
		), 
	);
	return $x;
}


#######################################################################################
# More complex areas to be seperated
#######################################################################################
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
	# check if $publisher_call fits to allowed letters is done in setup()
	my $publisher_call=$obj->q->param("publisher_call");
	if ( ($publisher_call) and ($obj->q->param("publisher_password")) ) {
		if ( -d $obj->get_priv_dir ) { 
			# we belive the login is succeeded if that directory exists
			$r.=$obj->render_user_pass_logout; 
			return $r; 
		} else {
			$r.="<h4>Login Failed, Try again</h4>";
			$r.=$obj->render_user_pass_login; 
			return $r; 
		}
	}
	if ( ($publisher_call) or ($obj->q->param("publisher_password")) ){
		$r.="<h4>only one, either your call or your pw received</h4>"; 
	}
	$r.=$obj->render_user_pass_login; 
	return $r; 
}

sub area_misc_buttons {
	my $obj=shift; 
	my $r; 
	my $mode=$obj->q->param("mode");
	if ( ! $mode ) { $mode="show_messages"; } 
	$r.="<table>"; 
		$r.="<tr>"; 
			if ( $obj->logged_in ) { 
				$r.="<td>";
					$obj->q->param("mode", "send_telegram"); 
					$r.=$obj->h_form({}, $obj->h_e("input", {type=>"submit", name=>"submit", value=>"send telegram"}));
					$mode=$obj->q->param("mode", $mode);
				$r.="</td>";
				if ( $obj->q->param("call") ) {
					$r.="<td>";
						$obj->q->param("mode", "change_trust"); 
						$r.=$obj->h_form({}, $obj->h_e("input", {type=>"submit", name=>"submit", value=>"change trust"}));
						$mode=$obj->q->param("mode", $mode);
					$r.="</td>";
				}
				$r.="<td>";
					$obj->q->param("mode", "sign_public_key"); 
					$r.=$obj->h_form({}, $obj->h_e("input", {type=>"submit", name=>"submit", value=>"sign key"}));
					$mode=$obj->q->param("mode", $mode);
				$r.="</td>";
				$r.="<td>";
					$obj->q->param("mode", "aliases_and_lists"); 
					$r.=$obj->h_form({}, $obj->h_e("input", {type=>"submit", name=>"submit", value=>"lists and aliases"}));
					$mode=$obj->q->param("mode", $mode);
				$r.="</td>";
			}
			if ( ! $obj->logged_in ) {
				$r.="<td>";
					$obj->q->param("mode", "register_publisher_login"); 
					$r.=$obj->h_form({}, 
						$obj->h_e("input", {type=>"submit", name=>"submit", value=>"register login"}),
					);
					$mode=$obj->q->param("mode", $mode);
				$r.="</td>";
			} 
		$r.="</tr>"; 
	$r.="</table>"; 
}

sub render_user_pass_login {
	my $obj=shift;
	my $r;  

	delete $obj->{qtc}->{exports}->{publisher_call};
	delete $obj->{qtc}->{exports}->{publisher_password};
	$r.=$obj->h_tabled_form({}, 
		$obj->h_labled_input({
			label=>"YOUR Callsign:", 
			type=>"text", 
			size=>10, 
			maxlength=>20, 
			name=>"publisher_call",
			value=>$obj->q->param("publisher_call"), 
		}),
		$obj->h_labled_input({
			label=>"YOUR Password:", 
			type=>"password", 
			size=>10, 
			maxlength=>50, 
			name=>"publisher_password",
			value=>$obj->q->param("publisher_password"), 
		}),
		$obj->h_submit_for_tbl({value=>"publischer login"}), 
	);
	$obj->{qtc}->{exports}->{publisher_call}=1;
	$obj->{qtc}->{exports}->{publisher_password}=1;
	
	#my $mode=$obj->param("mode");
	#$obj->param("mode", "register_publisher_login"); 
	#$r.=$obj->h_form({}, $obj->h_e("input", {type=>"submit", name=>"submit", value=>"register login"}));
	#$mode=$obj->param("mode", $mode); 
	
	return $r;
}

sub render_user_pass_logout {
	my $obj=shift; 
	my $r;  
	delete $obj->{qtc}->{exports}->{publisher_call};
	delete $obj->{qtc}->{exports}->{publisher_password};
	$r.=$obj->h_tabled_form({}, 
		"<tr><td><b>YOUR Callsign:</b></td><td>".$obj->q->param("publisher_call")."</td></tr>",
		$obj->h_submit_for_tbl({value=>"publischer logout"}), 
	);
	$obj->{qtc}->{exports}->{publisher_call}=1;
	$obj->{qtc}->{exports}->{publisher_password}=1;

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

sub js_confirm {
	my $obj=shift; 
	my $text=shift; 
	return "if(confirm('".$text."')) this.form.submit(); else return false;";
}



###############################################################
# webapp modes 
##############################################################
sub mode_show_messages {
	my $obj=shift; 
	my $q=$obj->query;
	if ( ! $q->param("type") ) { $q->param("type", "new"); }
	my $type=$q->param("type");
	if ( $type !~ /^((all)|(new)|(sent))$/ ) { return "<h1>FAIL telegram type invalid</h1>"; }
	my $r; 
	$r.="<table width=\"100%\">\n";
	$r.="<td align=\"left\">".$obj->area_ask_call."</td>\n";
	$r.="<td align=\"center\">".$obj->area_misc_buttons."</td>\n";
	$r.="<td align=\"right\">".$obj->area_user_pass."</td>\n";
	$r.="</table><hr/>";

	if ( ! $q->param("call") ) { return $r."<h3>Please enter a Call</h3>"; }

	$r.="<h3>$type qtc telegrams for ".$q->param("call").":</h3>";
	my @msgs=$obj->qtc_query->list_telegrams($q->param("call"), $type);
	my @rows; 
	foreach my $msg (@msgs) {  
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

sub mode_register_publisher_login {
	my $o=shift; 

	my $r; 

	if ( $o->q->param("submit") ) { 
		# this means we have to create a user account but first 
		# we should check a few things...
		my $ok=1; 
		if ( ! $o->q->param("publisher_call") ) {
			$ok=0;
			$r.="<h4>ERROR: The publisher call is empty!</h4>"; 
		}
		if ( $o->q->param("publisher_password") ne $o->q->param("publisher_password") ) {
			$ok=0;
			$r.="<h4>ERROR: Passwords are not the same</h4>"; 
		}
		if ( $o->{qtc}->{captcha}->check_code($o->q->param("captcha"),$o->q->param("captcha_token")) < 1 ) {
			$ok=0;
			$r.="<h4>ERROR: captcha verification failed</h4>"; 
		}
		if ( $o->publisher_exists ) {
			$ok=0;
			$r.="<h4>ERROR: Your Callsign is already registered here</h4>"; 
		}
		if ( $ok ) {
			$o->{qtc}->{publish}=qtc::publish->new(
				path=>$o->{qtc}->{path}, 
				rsa_keygen=>1,
				privpath=>$o->get_priv_dir, 
				call=>$o->q->param("publisher_call"),
				password=>$o->q->param("publisher_password"),
			); 
			$o->q->param("mode", "show_messages"); 
			return $o->mode_show_messages; 
		}
	}

	delete $o->{qtc}->{exports}->{publisher_call};
	delete $o->{qtc}->{exports}->{publisher_password};
	$r.="<h3>Enter login credentials:</h3>";
	$r.="<center>";
	$r.=$o->h_tabled_form({},
		$o->h_labled_input({
			label=>"YOUR Callsign:", 
			type=>"text", 
			size=>10, 
			maxlength=>20, 
			name=>"publisher_call",
			value=>$o->q->param("publisher_call"), 
		}),
		$o->h_labled_input({
			label=>"Password:", 
			type=>"password", 
			size=>10, 
			maxlength=>50, 
			name=>"publisher_password",
			value=>$o->q->param("publisher_password"), 
		}),
		$o->h_labled_input({
			label=>"Verify Password:", 
			type=>"password", 
			size=>10, 
			maxlength=>50, 
			name=>"verify_publisher_password",
			value=>$o->q->param("verify_publisher_password"), 
		}),
		$o->h_captcha({}),
		$o->h_submit_for_tbl({
			onClick=>$o->js_confirm("Do you really want to create an account for your callsign?"),
			value=>"create user",
		}), 
	);
	$o->{qtc}->{exports}->{publisher_call}=1;
	$o->{qtc}->{exports}->{publisher_password}=1;

	$r.="</center>";
	return $r; 
}

# this will return one of the captcha images 
sub mode_captcha_image {
	my $o=shift; 

	$o->header_add( -type => 'image/png' );
	$o->{disable_postrun}=1; 
	if ( ! $o->q->param("token") ) { die "I need a token for this mode"; }
	my $token=$o->q->param("token"); 
	if ( $token !~ /^([a-f0-9])+$/ ) { die "some characters in the token are not allowed\n"; }

	my $path=$o->{qtc}->{captcha_output_dir}."/".$token.".png"; 
	if ( ! -f $path ) { die "The captcha token is not there"; }

	my $r; 
	open(READ, "< ".$path) or die "cant open $path\n"; 
	while(<READ>) { $r.=$_; }
	close READ; 
	
	return $r; 
}

1;
