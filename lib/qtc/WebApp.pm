package qtc::WebApp; 

use base 'CGI::Application'; 
use qtc::query; 
use qtc::publish; 
use Data::Dumper; 
use Digest::SHA qw(sha256_hex); 
use POSIX qw(strftime); 
use Authen::Captcha; # the Application Captcha plugin was not installable
use File::Copy; 


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
		-script=>$obj->js_post_function, 
	); 

	$out.=$obj->h_e("center", {}, 
		$obj->h_h1({}, '<a href="'.$obj->{qtc}->{home_page}.'">QTC Net Web Access</a>'),
		'<small>a microblogging (like twitter) and messaging system for ham radio (still in testing)</small>'
		
	); 
	$out.=$obj->h_e("hr"); 
	$out.=$$out_ref; 

	$out.=$cgi->end_html; 
	
	# return output.... 
	$$out_ref=$out; 
}

sub setup {
	my $obj = shift;
	$obj->start_mode('show_telegrams');
	$obj->mode_param('mode');
	$obj->run_modes(
		'captcha_image' => 'mode_captcha_image',
		'show_telegrams' => 'mode_show_telegrams',
		'register_publisher_login' => 'mode_register_publisher_login',
		'key_management' => 'mode_key_management',
		'pubkey_download' => 'mode_pubkey_download',
		'send_telegram' => 'mode_send_telegram',
		'change_password' => 'mode_change_password',
		'change_trust' => 'mode_change_trust',
		'aliases_and_followings' => 'mode_aliases_and_followings',
		'latest_changes' => 'mode_latest_changes',
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
		$obj->qtc_query->ensure_path($obj->{qtc}->{captcha_data_dir});
		$obj->qtc_query->ensure_path($obj->{qtc}->{captcha_output_dir}); 
		$obj->{qtc}->{captcha}=Authen::Captcha->new(
			data_folder=>$obj->{qtc}->{captcha_data_dir},
			output_folder=>$obj->{qtc}->{captcha_output_dir},
		); 
	}

	if ( ! $obj->{qtc}->{home_page} ) { $obj->{qtc}->{home_page}=$obj->q->url(-full=>1); }

	$obj->{qtc}->{exports}->{mode}=1;
	$obj->{qtc}->{exports}->{call}=1;
	$obj->{qtc}->{exports}->{type}=1;
	$obj->{qtc}->{exports}->{publisher_call}=1;
	$obj->{qtc}->{exports}->{publisher_password}=1;
	$obj->{qtc}->{exports}->{list_max_items}=1;
	$obj->{qtc}->{exports}->{list_offset}=1;
	
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
			path=>$o->{qtc}->{path}, 
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
	if ( ! $obj->{qtc}->{priv_dir} ) {
		my $user=$obj->q->param("publisher_call");
		my $pass=$obj->q->param("publisher_password");
		my $user_pass_sha=$obj->qtc_query->call2fname($user)."_".sha256_hex($pass);
		$obj->{qtc}->{priv_dir}=$obj->{qtc}->{priv_path_prefix}."/".$user_pass_sha;
	}
	return $obj->{qtc}->{priv_dir}; 
}

sub filter_qsp_makes_sense {
	my $obj=shift;
	my $type=$obj->q->param("type"); 
	if ( $type !~ /^(new|timeline_new)$/ ) { return; }
	return @_; 
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
		foreach my $val ( $obj->q->param($p) ) {
			$r.=$obj->h_e("input", {
					type=>"hidden", 
					name=>$p,
					value=>$val,
				}
			);
		} 
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

sub h_call_lnk {
	my $obj=shift; 
	my $p=shift;
	my @content=@_; 
	if ( $#content < 0 ) { push @content, $p->{call}; } 

	delete $obj->{qtc}->{exports}->{call}; 
	delete $obj->{qtc}->{exports}->{mode}; 
	my $r='<a href="javascript:void(0);" onClick="'.$obj->js_post_exec(mode=>"show_telegrams", call=>$p->{call}).'">';
	$r.=join("", @content); 
	$r.="</a>";
	$obj->{qtc}->{exports}->{call}=1; 
	$obj->{qtc}->{exports}->{mode}=1; 

	return $r; 
}

sub h_form {
	my $obj=shift;
	my $p=shift; 
	if ( ! $p->{action} ) { $p->{action}=$obj->q->url(-full=>1); }
	if ( ! $p->{method} ) { $p->{method}="POST"; }
	my @r=@_; 
	my $x=$obj->h_e("form", $p, 
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
		$obj->h_e("td", {align=>"left"},
			$obj->h_e("input", $p),
		), 
	);
}

sub h_telegram_types_button {
	my $obj=shift; 
	my $p=shift; 
	my $mode=$obj->q->param("type");
	if ( ! $mode ) { $mode="show_telegrams"; } 
	my $r; 
	my %opts=(
		type=>"submit", 
		name=>"submit", 
		value=>$p->{value},	
	);
	if ( $mode eq $p->{type} ) {
		$opts{disabled}="disabled"; 
	}
	$r.="<td>";
		$obj->q->param("type", $p->{type}); 
		$r.=$obj->h_form({}, $obj->h_e("input", \%opts));
		$mode=$obj->q->param("type", $mode);
	$r.="</td>";
	return $r; 
}

sub h_misc_button {
	my $obj=shift; 
	my $p=shift; 
	my $mode=$obj->q->param("mode");
	if ( ! $mode ) { $mode="show_telegrams"; } 
	my $r;
	my %opts=(
		type=>"submit", 
		name=>"submit", 
		value=>$p->{value},	
	);
	if ( $mode eq $p->{mode} ) {
		$opts{disabled}="disabled"; 
	}
	$r.="<td>";
		$obj->q->param("mode", $p->{mode}); 
		$r.=$obj->h_form({}, $obj->h_e("input", \%opts));
		$mode=$obj->q->param("mode", $mode);
	$r.="</td>";
	return $r; 
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
	my $mode=$obj->q->param("mode");
	if ( ! $mode ) { $mode="show_telegrams"; } 
	$obj->q->param("mode", "show_telegrams");
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
	$obj->q->param("mode", $mode);

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

# renders new all sent buttons for the telegram followings
sub area_telegram_types_buttons {
	my $obj=shift; 
	my $r; 


	# handle maxitems and offset 
	my $maxitems=$obj->q->param("list_max_items");
	if ( $maxitems !~ /^\d\d?\d?$/  ) { 
		$maxitems=20; 
		$obj->q->param("list_max_items", $maxitems);
	}
	my $offset=$obj->q->param("list_offset");
	if ( $maxitems !~ /^\d+$/  ) { 
		$offset=0; 
		$obj->q->param("list_offset", $offset);
	}
	if ( $obj->q->param("newoffset") eq "<<" ) { 
		$obj->q->param("list_offset", 0);
		$obj->q->delete("newoffset");
	}
	if (( $obj->q->param("newoffset") eq "<" ) and ( $offset > 0 ) ) { 
		$obj->q->param("list_offset", $obj->q->param("list_offset")-1);
		$obj->q->delete("newoffset");
	}
	if ( $obj->q->param("newoffset") eq ">" ) { 
		$obj->q->param("list_offset", $obj->q->param("list_offset")+1);
		$obj->q->delete("newoffset");
	}

	# read call from parameters 
	my $call=$obj->q->param("call");
	$call=$obj->qtc_query->allowed_letters_for_call($call); 

	#$r.="<b>Show me: </b>";
	$r.='<table width="100%"><tr><td align="left">';
		$r.="<table><tr>";
		delete $obj->{qtc}->{exports}->{list_offset};
		foreach my $what ("new", "timeline_new", "timeline", "all", "sent") {
			if ( ! defined $obj->{num_telegrams}->{$what} ) { 
				$obj->{num_telegrams}->{$what}=$obj->qtc_query->num_telegrams($call, $what); 
			}
			$r.=$obj->h_telegram_types_button({
				type=>"$what",
				value=>"$what (".$obj->{num_telegrams}->{$what}.")"
			});
		}
		$obj->{qtc}->{exports}->{list_offset}=1;
		$r.="</tr></table>";
	$r.='</td><td align="right">';
	delete $obj->{qtc}->{exports}->{list_max_items};
	$r.=$obj->h_form({}, 
		"<table><tr><td>",
		$obj->h_e("input", {
			type=>"submit",
			name=>"newoffset",
			value=>"<<"
		}),"</td><td>",
		$obj->h_e("input", {
			type=>"submit",
			name=>"newoffset",
			value=>"<"
		}),"</td><td>",
		$obj->h_e("input", {
			size=>2,
			maxlength=>5,
			type=>"text",
			name=>"list_max_items",
			value=>$maxitems
		}),"</td><td>",
		$obj->h_e("input", {
			type=>"submit",
			name=>"newoffset",
			value=>">"
		}),
		"</td></tr></table>",
	);
	$obj->{qtc}->{exports}->{list_max_items}=1;

	$r.="</td></tr></table>";

	return $r;
}


sub area_misc_buttons {
	my $obj=shift; 
	my $r; 
	my $mode=$obj->q->param("mode");
	if ( ! $mode ) { $mode="show_telegrams"; } 
	$r.="<table>"; 
		$r.="<tr>"; 
			$r.=$obj->h_misc_button({
				mode=>"latest_changes", 
				value=>"latest changes",
			}); 
			$r.=$obj->h_misc_button({
				mode=>"show_telegrams", 
				value=>"show telegrams",
			}); 
			if ( $obj->logged_in ) { 
				$r.=$obj->h_misc_button({
					mode=>"send_telegram", 
					value=>"send telegram",
				}); 
				if ( $obj->q->param("call") ) {
					if ( $obj->qtc_query->has_operator($obj->q->param("call"))) {
						$r.=$obj->h_misc_button({
							mode=>"change_trust", 
							value=>"change trust",
						}); 
					} 
				} 
				$r.="</tr><tr>";
				$r.=$obj->h_misc_button({
					mode=>"key_management", 
					value=>"key management",
				}); 
				$r.=$obj->h_misc_button({
					mode=>"aliases_and_followings", 
					value=>"aliases and followings",
				}); 
				$r.=$obj->h_misc_button({
					mode=>"change_password", 
					value=>"change password",
				}); 
			}
			if ( ! $obj->logged_in ) {
				$r.=$obj->h_misc_button({
					mode=>"register_publisher_login", 
					value=>"register login",
				}); 
			} 
		$r.="</tr>"; 
	$r.="</table>"; 
}

sub area_navigation {
	my $obj=shift; 
	my $r; 

	$r.="<table width=\"100%\">\n";
	$r.="<td align=\"left\">".$obj->area_ask_call."</td>\n";
	$r.="<td align=\"center\">".$obj->area_misc_buttons."</td>\n";
	$r.="<td align=\"right\">".$obj->area_user_pass."</td>\n";
	$r.="</table><hr/>";
	
	return $r; 
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
		$obj->h_submit_for_tbl({value=>"publisher login"}), 
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
	delete $obj->{qtc}->{exports}->{mode};
	$r.=$obj->h_tabled_form({}, 
		"<tr><td><b>YOUR Callsign:</b></td><td>".$obj->q->param("publisher_call")."</td></tr>",
		$obj->h_submit_for_tbl({value=>"publisher logout"}), 
	);
	$obj->{qtc}->{exports}->{publisher_call}=1;
	$obj->{qtc}->{exports}->{publisher_password}=1;
	$obj->{qtc}->{exports}->{mode}=1;

	return $r;
}

sub render_latest_changes {
	my $o=shift; 

	my $r;
	
	$r.='<h3>Latest Changes:</h3>';

	foreach my $msg ($o->qtc_query->latest_changes(40) ) {
		if ( $msg->type eq 'telegram' ) {
			$r.='<p><b>'.$msg->call.'</b> published a telegram:<table align="center" width="70%"><tr><td>';
			$r.=$o->format_telegram_in_html($msg);
			$r.='</td></tr></table></p>'; 
			next; 
		}
		if ( $msg->type eq 'qsp' ) {
			$r.='<p><b>'.$msg->call.'</b> delivered telegram number '.$msg->hr_refnum($msg->telegram_checksum).
				' to '.$msg->to.' at '.strftime("%Y-%m-%d %H:%M:%S UTC", gmtime($msg->qsp_date)).'</p>'; 
			next; 
		}
		if ( $msg->type eq 'pubkey' ) {
			$r.='<p><b>'.$msg->call.'</b> added a key</p>'; 
			next; 
		}
		if ( $msg->type eq 'revoke' ) {
			$r.='<p><b>'.$msg->call.'</b> revoked a key</p>'; 
			next; 
		}
		if ( $msg->type eq 'trust' ) {
			$r.='<p><b>'.$msg->call.'</b> sets trustlevel of '.$msg->to.' to '.$msg->trustlevel.'</p>'; 
			next; 
		}
		if ( $msg->type eq 'operator' ) {
			$r.='<p><b>'.$msg->call.'</b> has updated his aliases and followings information</p>'; 
			next; 
		}
		$r.='<p><b>'.$msg->call.'</b> has send a '.$msg->type.' message</p>'; 
	}
 
	return $r; 
}

sub format_telegram_in_html {
	my $o=shift; 
	my $msg=shift; 
	my $r; 
	$r.=$o->h_table({}, 
		$o->h_tr({}, 
			$o->h_td({}, "<b>number:</b> ".$msg->hr_refnum),
			$o->h_td({colspan=>2}, "<b>publisher:</b> ".$o->h_call_lnk({call=>$msg->call})),
		),
		$o->h_tr({}, 
			$o->h_td({}, "<b>from:</b> ".$o->h_call_lnk({call=>$msg->from})),
			$o->h_td({}, "<b>to:</b> ".$o->h_call_lnk({call=>$msg->to})),
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

sub js_post_exec {
	my $obj=shift; 
	my %parm=@_;
	my $r="post('".$obj->q->escapeHTML($obj->q->url(-full=>1))."',{";
	foreach my $p (keys %{$obj->{qtc}->{exports}}) {
		foreach my $val ( $obj->q->param($p) ) {
			$val=~s/\'//g;
			$r.=$obj->q->escapeHTML($p).": '".$obj->q->escapeHTML($val)."', ";
		} 
	}
	foreach my $p (keys %parm) {
		$parm{$p}=~s/\'//g; 	
		$r.=$obj->q->escapeHTML($p).": '".$obj->q->escapeHTML($parm{$p})."', ";
	}
	chop($r); # remove " " 
	chop($r); # remove ","
	$r.="});";
	return $r; 
}

sub js_post_function {
	my $obj=shift; 
	return '
function post(path, params, method) {
method = method || "post"; // Set method to post by default if not specified.

// The rest of this code assumes you are not using a library.
// It can be made less wordy if you use one.
var form = document.createElement("form");
form.setAttribute("method", method);
form.setAttribute("action", path);

for(var key in params) {
    if(params.hasOwnProperty(key)) {
        var hiddenField = document.createElement("input");
        hiddenField.setAttribute("type", "hidden");
        hiddenField.setAttribute("name", key);
        hiddenField.setAttribute("value", params[key]);

        form.appendChild(hiddenField);
     }
}

document.body.appendChild(form);
form.submit();

}
';
}


###############################################################
# webapp modes 
##############################################################
sub mode_show_telegrams {
	my $obj=shift; 
	my $q=$obj->query;
	if ( ! $q->param("type") ) { $q->param("type", "new"); }
	my $type=$q->param("type");
	if ( $type !~ /^((all)|(new)|(sent)|(timeline)|(timeline_new))$/ ) { return "<h1>FAIL telegram type invalid</h1>"; }
	my $r; 

	if ( ( $obj->logged_in ) and ( ! $q->param("call") ) ) {
		$q->param("call", $q->param("publisher_call"));
		#$r.="<h3>You may search for telegrams to other calls in the upper left, I display the telegrams to YOUR publisher call until then</h3>"; 
	}

	#we have to check if we have a reply to set bevore we are doing any navigation bar stuff
	# we will escape to sent send telegram then 
	foreach my $reply (grep {/^reply_to_([0-9]|[a-f])+$/} $obj->q->param()) {
		$reply=~s/^reply_to_//g; 
		$obj->q->param("mode", "send_telegram"); 
		$obj->q->param("reply", $reply); 
		return $obj->mode_send_telegram; 
	}


	$r.=$obj->area_navigation; 

	if ( ! $q->param("call") ) { 
		$r.="<h3>Please enter a call in the upper left corner or login in the upper right one.</h3>";
		$r.='<p></p>
<p>QTC Net is a relay system for messages form of telegrams for amateur radio. It\'s goal is to establish the 
communication between stations that who can not reach themself directly. </p>
<p>A delivery agent can receive telegrams from a remote station during a qso. The received telegrams 
will be published by him. A delivery agent can send telegrams to the remote station. The telegrams will be marked 
as delivered in the qtc-net by him. </p>';
		$r.='<p>you may browse to 
<a href="'.$obj->{qtc}->{home_page}.'">'.$obj->{qtc}->{home_page}.'</a> if you want more information</p>';
		$r.='<hr/>';
		$r.=$obj->render_latest_changes; 
		return $r; 
 
	}

	#prepare qsp checksum hash
	my %qsp; 
	foreach $chk ($q->param("qsp")) { $qsp{$chk}=1; }

	$r.="<h3>$type qtc telegrams for ".$q->param("call").":</h3>";
	
	$r.=$obj->area_telegram_types_buttons;

	my @msgs=$obj->qtc_query->list_telegrams($q->param("call"), $type, $q->param("list_max_items"), $q->param("list_offset"));
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
			$obj->h_td({}, $obj->format_telegram_in_html($msg)),
			$obj->filter_login_required(
			$obj->h_td({}, $obj->h_e("input", {
				type=>"submit", 
				name=>"reply_to_".$msg->checksum, 
				value=>"reply",
			})),
			),
			$obj->filter_qsp_makes_sense(
			$obj->filter_login_required(
				$obj->h_td({}, $obj->h_e("input", {type=>"checkbox", name=>"qsp", value=>$msg->checksum})),
			), 
			), 
		); 
	} 	

	$r.=$obj->h_e("center",{}, $obj->h_form({}, 
		$obj->h_table({width=>'70%'}, 
			$obj->h_tr({},
				$obj->h_td({}), 
				$obj->filter_login_required(
				$obj->h_td({}),
				),
				$obj->filter_qsp_makes_sense(
				$obj->filter_login_required(
					$obj->h_td({}, $obj->h_e("input", {
						type=>"submit", 
						name=>"submit", 
						value=>"QSP sel.",
						onClick=>$obj->js_confirm("Have you really forwarded the checked messages to $call?"),
					})),
				), 
				), 
			),
			@rows,
			$obj->h_tr({},
				$obj->h_td({}), 
				$obj->filter_login_required(
				$obj->h_td({}),
				),
				$obj->filter_qsp_makes_sense(
				$obj->filter_login_required(
					$obj->h_td({}, $obj->h_e("input", {
						type=>"submit", 
						name=>"submit", 
						value=>"QSP sel.",
						onClick=>$obj->js_confirm("Have you really forwarded the checked messages to $call?"),
					})),
				), 
				), 
			),
		), 
	)); 

	$r.=$obj->area_telegram_types_buttons;

	return $r; 
}

sub mode_register_publisher_login {
	my $o=shift; 

	my $r; 
	$r.=$o->area_navigation; 

	if ( $o->q->param("captcha_token") ) { 
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
			$o->q->param("mode", "show_telegrams"); 
			return $o->mode_show_telegrams; 
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

# this will return one of the captcha images 
sub mode_key_management {
	my $o=shift; 
	my $r; 
	
	if ( $o->q->param("revoke.qtc") ) {
			my $fh=$o->q->param("revoke.qtc");
			$r.="<h4>got a file upload</h4>";
			my $x; 
			while ($_=<$fh>) { $x.=$_; }
		eval { 
			$o->qtc_publish->revoke(hex=>unpack("H*", $x)); 
		}; 
		if ( $@ ) {
			print STDERR $@; # i want to see what went wrong. 
			$r.="<h4>errors during upload</h4>";
		} else { 
			$o->q->param("mode", "show_telegrams"); 
			return $o->mode_show_telegrams; 
		}
	} 
	if ( $o->q->param("pubkey.qtc") ) {
			my $fh=$o->q->param("pubkey.qtc");
			$r.="<h4>got a file upload</h4>";
			my $x; 
			while ($_=<$fh>) { $x.=$_; }
		eval { 
			$o->qtc_publish->pubkey(hex=>unpack("H*", $x)); 
		}; 
		if ( $@ ) {
			print STDERR $@; # i want to see what went wrong. 
			$r.="<h4>errors during upload</h4>";
		} else { 
			$o->q->param("mode", "show_telegrams"); 
			return $o->mode_show_telegrams; 
		}
	} 
	
	$r.=$o->area_navigation; 

	$r.="<h3>Public Key Download</h3> 
		<p>You can Download your selfsigned public key message to get it signed and published 
		with one of your other accounts/private keys, to activate this one.</p>";
	$r.="<center>"; 
	
	my $mode=$o->q->param("mode");
	$o->q->param("mode", "pubkey_download"); 
	$r.=$o->h_form({}, 
		'<input type="hidden" name="key_type" value="pubkey"></input>',
		$o->h_e("input", {type=>"submit", name=>"submit", value=>"pubkey download"}),
	);
	$mode=$o->q->param("mode", $mode);
	
	$r.="</center>"; 
	
	$r.="<h3>Public Key Upload</h3> 
		<p>You can Upload a public key from another of YOUR accounts/private keys to get it 
		signed and published on by this system.</p>";
	$r.="<center>"; 
	$r.=$o->h_tabled_form({enctype=>"multipart/form-data"},
		$o->h_labled_input({
			label=>"Public Key QTC:", 
			type=>"file",
			name=>"pubkey.qtc",
			size=>50, 
			maxlength=>1000,
		}),
		$o->h_submit_for_tbl({value=>"Upload"}), 
	);
	$r.="</center>"; 
	
	$r.="<h3>Revoke Message Download</h3> 
		<p>You SHOULD (BUT WE KNOW YOU WONT) download the revoke message for this 
		key and store it at a save place. Wenn this message is published it means 
		that the private key of this account is not valid anymore.</p>";
	$r.="<center>"; 
	my $mode=$o->q->param("mode");
	$o->q->param("mode", "pubkey_download"); 
	$r.=$o->h_form({}, 
		'<input type="hidden" name="key_type" value="revoke"></input>',
		$o->h_e("input", {type=>"submit", name=>"submit", value=>"revoke download"})
	);
	$mode=$o->q->param("mode", $mode);
	$r.="</center>"; 
	
	$r.="<h3>Revoke Message Upload</h3> 
		<p>You can Upload a revoke key message for a public key account if you 
		have downloaded and stored it earlier. The message can be from another 
		account/key but it should be valid.</p>";
	$r.="<center>"; 
	$r.=$o->h_tabled_form({enctype=>"multipart/form-data"},
		$o->h_labled_input({
			label=>"Revoke Key QTC:", 
			type=>"file",
			name=>"revoke.qtc",
			size=>50, 
			maxlength=>1000,
		}),
		$o->h_submit_for_tbl({value=>"Upload"}), 
	);
	$r.="</center>"; 
	
	return $r; 
}

# this will return a public or private key 
sub mode_pubkey_download {
	my $o=shift; 
	my $r; 

	if ( ! $o->logged_in ) { return "Access denied"; }
	my $msg; 
	if ( $o->q->param("key_type") eq "pubkey" ) {
		$msg=$o->qtc_publish->get_public_key_msg; 
	} elsif ( $o->q->param("key_type") eq "revoke" ) {
		$msg=$o->qtc_publish->revoke(
			download=>1,
		); 
	}
	if ( ! $msg ) { return "i dont have a message, either key_type or a login is missing\n"; }
	
	$o->header_add(
		-type => 'application/octet-stream',
		-attachment => $msg->filename,
	);
	$o->{disable_postrun}=1; 

	return pack("H*", $msg->as_hex); 
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

	if ( $o->q->param("reply") ) {
		my $reply=$o->q->param("reply"); 
		if (
			( $reply =~ /^([a-f]|[0-9])+$/ ) 
				and 
			( length($reply) == 64 ) 
		) { # ok this looks really like a checksum 
			my $reply=$o->qtc_query->telegram_by_checksum($reply); 
			if ( $reply ) {
				$r.="<h4>original Message: </h4>";
				$r.="<center><table width=\"90\%\"><tr><td>"; 
				$r.=$o->format_telegram_in_html($reply);
				$r.="</td></tr></table></center><br/><br/><h4>Reply:</h4>"; 
				if ( ! $o->q->param("to") ) { $o->q->param("to", $reply->from); }
			}
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


sub mode_change_password {
	my $o=shift; 

	my $r; 
	$r.=$o->area_navigation; 

	if ( ! $o->logged_in ) { return "<h4>ERROR Please log in first</h4>"; }

	if ( $o->q->param("new_publisher_password") ) { 
		my $ok=1; 
		if ( $o->q->param("new_publisher_password") ne $o->q->param("verify_publisher_password")) {
			$ok=0;
			$r.="<h4>ERROR: The new passwords don't match</h4>"; 
		}
		if ( $ok ) {
			my $oldpath=$o->get_priv_dir;
			$o->q->param("publisher_password", $o->q->param("new_publisher_password"));
			delete $o->{qtc}->{priv_dir}; 
			if ( -e $o->get_priv_dir ) { return "<h1>BAD REQUEST, TARGET USERNAME PW ALREADY EXIST</h1>"; }
			move($oldpath, $o->get_priv_dir) or return "<h1>password reset failed at move stage</h1>"; 
			delete $o->{qtc}->{publish}; 

			$o->q->param("mode", "show_telegrams"); 
			return $o->mode_show_telegrams; 
		}
	}

	delete $o->{qtc}->{exports}->{publisher_password};
	$r.="<h3>Enter login credentials:</h3>";
	$r.="<center>";
	$r.=$o->h_tabled_form({},
		$o->h_labled_input({
			label=>"Current Password:", 
			type=>"password", 
			size=>10, 
			maxlength=>50, 
			name=>"publisher_password",
			value=>$o->q->param("publisher_password"), 
		}),
		$o->h_labled_input({
			label=>"New Password:", 
			type=>"password", 
			size=>10, 
			maxlength=>50, 
			name=>"new_publisher_password",
			value=>$o->q->param("new_publisher_password"), 
		}),
		$o->h_labled_input({
			label=>"Verify New Password:", 
			type=>"password", 
			size=>10, 
			maxlength=>50, 
			name=>"verify_publisher_password",
			value=>$o->q->param("verify_publisher_password"), 
		}),
		$o->h_submit_for_tbl({
			onClick=>$o->js_confirm("Do you really want to change the password for your callsign?"),
			value=>"change password",
		}), 
	);
	$o->{qtc}->{exports}->{publisher_password}=1;

	$r.="</center>";
	return $r; 
}


#############################################
# normally the keys should also be checked 
# but thats an implementation thing 
############################################
sub mode_change_trust {
	my $o=shift; 

	my $r; 
	$r.=$o->area_navigation; 

	if ( ! $o->logged_in ) { return "<h4>ERROR Please log in first</h4>"; }

	if ( ! $o->q->param("call") ) { 
		$r.="<h4>I need a call to set a trustlevel for</h4>";
		return $r;  
	} elsif (! $o->qtc_query->operator($o->q->param("call"))) { 
		$r.="<h4>This call does not have an operator message we can trust</h4>";
		return $r;  
	} 
	if (
			( defined $o->q->param("trustlevel") )
			and
			( $o->q->param("trustlevel") <= 1 )
			and 
			( $o->q->param("trustlevel") >= -1 )
	) { 
		$o->qtc_publish->trust(
			to=>$o->q->param("call"), 
			trustlevel=>$o->q->param("trustlevel"),
		);
		$o->q->param("mode", "show_telegrams"); 
		return $o->mode_show_telegrams; 
	}

	my $msg=$o->qtc_query->get_old_trust(
		call=>$o->q->param("publisher_call"),
		to=>$o->q->param("call"),
	);
	my $trustlevel=0; 
	if ( $msg ) { $trustlevel=$msg->trustlevel; }
	my @chk0; if ( $trustlevel == 0 ) { @chk0=("checked", "checked"); }
	my @chk1; if ( $trustlevel == 1 ) { @chk1=("checked", "checked"); } 
	my @chk_neg; if ( $trustlevel == -1 ) { @chk_neg=("checked", "checked"); } 

	$r.="<h3>Set Your Trust for ".$o->q->param("call").":</h3>";
	$r.="<center>";
	$r.=$o->h_tabled_form({},
		$o->h_labled_input({
			label=>"I absolutely trust this call:", 
			type=>"radio", 
			name=>"trustlevel",
			value=>1,
			@chk1, 
		}),
		$o->h_labled_input({
			label=>"I don't care:", 
			type=>"radio", 
			name=>"trustlevel",
			value=>0,
			@chk0, 
		}),
		$o->h_labled_input({
			label=>"I would not trust this call:", 
			type=>"radio", 
			name=>"trustlevel",
			value=>"-1",
			@chk_neg, 
		}),
		$o->h_submit_for_tbl({
			onClick=>$o->js_confirm("Do you really want to change the trustlevel for this callsign?"),
			value=>"change trustlevel",
		}), 
	);

	$r.="</center>";
	return $r; 
}

sub apply_deletion_array {
	my $o=shift; 
	my $aref=shift; 
	my @delarray=@_;
	
	# buld delhash 
	my %delhash; 
	foreach my $del ( @delarray ) { if ( $del ) { $delhash{$del}=1; } }

	my @ret; 
	foreach my $entry (@$aref) { 
		if ( ! $entry ) { next; } 
		if ( $delhash{$entry} ) { next; }
		$delhash{$entry}=1; 
		push @ret, $entry; 
	}
	return sort(@ret); 
}

sub mode_aliases_and_followings {
	my $o=shift; 

	my $r;
	$r.=$o->area_navigation; 

	if ( ! $o->logged_in ) { return "<h4>ERROR Please log in first</h4>"; }

	my @aliases=$o->q->param("aliases"); 
	my @followings=$o->q->param("followings"); 

	# get aliases and followings from this operator 
	if ( 
		( $#aliases==-1 ) and ( $#followings==-1 ) 
	) { 
		my $op=$o->qtc_query->operator($o->q->param("publisher_call")); 
		if ( $op ) {
			@aliases=$op->set_of_aliases; 
			@followings=$op->set_of_followings; 
		}
	}

	push @aliases, $o->qtc_query->allowed_letters_for_call($o->q->param("add_alias")); 
	push @followings, $o->qtc_query->allowed_letters_for_call($o->q->param("add_following")); 
	@aliases=$o->apply_deletion_array(\@aliases, $o->q->param("delete_alias")); 
	@followings=$o->apply_deletion_array(\@followings, $o->q->param("delete_following")); 

	if ( $o->q->param("save_changes") eq "really" ) {
		# send operator here 
		$o->qtc_publish->operator(
			set_of_aliases=>[@aliases],
			set_of_followings=>[@followings],
		); 
		$o->q->param("mode", "show_telegrams"); 
		# we had the problem here that sometimes the processor may catch a telegram right under 
		# the ass of the show_telegram method, so we try to look at the new telegrams to reduce that risk
      # otherwise we could use a sleep here.
		# the problem is an internal server error.....  
		$o->q->param("type", "new");
		return $o->mode_show_telegrams; 
	}

	if ( $#aliases==-1 ) {
		$o->q->delete("aliases"); 
	} else { 
		$o->q->param("aliases", @aliases); 
	}
	if ( $#followings==-1 ) {
		$o->q->delete("followings"); 
	} else { 
		$o->q->param("followings", @followings);
	}
	
	$r.='<p>Don\'t forget to save your changes when you are done</p>';

	$r.="<h3>Aliases of ".$o->q->param("publisher_call").":</h3>";
	
	$o->{qtc}->{exports}->{aliases}=1; 
	$o->{qtc}->{exports}->{followings}=1; 

	my $x; 
	foreach my $alias (@aliases) {
		$x.=$o->h_labled_input({
			label=>$alias,
			type=>"checkbox",
			name=>"delete_alias",
			value=>$alias,
		}); 
	}
	$r.='<center>';
	$r.=$o->h_tabled_form({}, 
		$x,
		$o->h_submit_for_tbl({
			value=>"remove selected"
		})
	); 
	$r.=$o->h_tabled_form({}, 
		$o->h_labled_input({
			label=>"add alias:", 
			type=>"text", 
			size=>10, 
			maxlength=>20, 
			name=>"add_alias",
		}),
		$o->h_submit_for_tbl({value=>"next"}), 
	);
	$r.='</center>';

	$r.="<h3>Calls that ".$o->q->param("publisher_call")." follows:</h3>";
	
	$x='';
	foreach my $following (@followings) {
		$x.=$o->h_labled_input({
			label=>$following,
			type=>"checkbox",
			name=>"delete_following",
			value=>$following,
		}); 
	}
	$r.='<center>';
	$r.=$o->h_tabled_form({}, 
		$x,
		$o->h_submit_for_tbl({
			value=>"remove selected"
		})
	); 
	$r.=$o->h_tabled_form({}, 
		$o->h_labled_input({
			label=>"add following:", 
			type=>"text", 
			size=>10, 
			maxlength=>20, 
			name=>"add_following",
		}),
		$o->h_submit_for_tbl({value=>"next"}), 
	);
	$r.='</center>';
	$r.='<center>';
	$r.='<br></br>';
	$r.='<br></br>';
	$r.=$o->h_form({},
		'<input type="hidden" name="save_changes" value="really"></input>', 
		$o->h_e("input", {
			type=>"submit", 
			name=>"submit", 
			value=>"SAVE CHANGES",
			onClick=>$o->js_confirm("Send your changes to aliases and followings back into the Network?"), 
		})
	);
	$r.='</center>';
 
	return $r; 
}


sub mode_latest_changes {
	my $o=shift; 

	my $r;
	$r.=$o->area_navigation; 
	
	$r.=$o->render_latest_changes; 
 
	return $r; 
}

1;
