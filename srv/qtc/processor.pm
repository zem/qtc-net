package qtc::processor; 
use qtc::msg; 
use File::Basename; 
use qtc::misc;
@ISA=(qtc::misc);

# this package does all the linking of a qtc-net message to its right folders 
sub new { 
   my $class=shift; 
   my %parm=(@_); 
   my $obj=bless \%parm, $class; 
	if ( ! $obj->{root} ) { 
		$obj->{root}=$ENV{HOME}."/.qtc"; 
	}
	if ( ! $obj->{key} ) { 
		$obj->{key}=$ENV{HOME}."/.qtckey"; 
	}
   return $obj; 
}


# this is to be used for any message that is not in /in
sub process_file { 
	my $obj=shift; 
	my $file=shift; 

	$msg=qtc::msg->new(
		filename=>basename($file),
		path=>dirname($file),
	); 
	$obj->write_msg_to_in($msg); 
	$obj->process($msg); 
}

# this is to be used for any message that is in /in
sub process_one_msg_from_in { 
	my $obj=shift; 
	my $file=shift; 

	$msg=qtc::msg->new(
		filename=>$file, 
		path=>$obj->{root}."/in",
	); 
	$obj->process($msg);
}

# this is to be used for any message that is in /in
sub process_in { 
	my $obj=shift; 

	foreach my $file ($obj->scan_dir($obj->{root}."/in", '.*\.xml')){
		if (( ! -e $obj->{root}."/out" ) and ( ! -e $obj->{root}."/bad" )) { 
			$msg=qtc::msg->new(
				filename=>$file, 
				path=>$obj->{root}."/in",
			); 
			$obj->process($msg);
		}
	} 
}

sub process_xml { 
	my $obj=shift; 
	my $xml=shift; 
	
	$msg=qtc::msg->new(
		xml=>$xml,
		path=>$obj->{root}."/in"
	); 
	$obj->write_msg_to_in($msg); 
	$obj->process($msg); 
}

sub write_msg_to_in {
	my $obj=shift; 
	my $msg=shift; 

	if ( -e $obj->{root}."/in/".$msg->filename ) { 
		die "ups this object ".$msg->filename." already exist in $obj->{root}/in \n" 
	}
	$msg->to_filesystem($obj->{root}."/in");
}

# so lets guess we have a message that is in $root/in 
# and it is not bad otherwise this message would be 
# linked to bad messages by the exception routine. 
sub process { 
	my $obj=shift; 
	my $msg=shift; # is a message object, which must have a file in /in
	
	if ( $msg->type eq "msg" ) { 
		$obj->import_msg($msg); 
		return; 
	}
	if ( $msg->type eq "qsp" ) { 
		$obj->import_qsp($msg); 
		return; 
	}
	if ( $msg->type eq "operator" ) { 
		$obj->import_operator($msg); 
		return; 
	}
	if ( $msg->type eq "pubkey" ) { 
		$obj->import_pubkey($msg); 
		return; 
	}
	if ( $msg->type eq "revoke" ) { 
		$obj->import_revoke($msg); 
		return; 
	}
	if ( $msg->type eq "trust" ) { 
		$obj->import_trust($msg); 
		return; 
	}
	# OK this message is unknown so message is bad
	$msg->link_to_path($obj->{root}."/bad"); 
}


################
# importing rules
sub import_msg {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here
	
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/allmsg");
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/sent");
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/newmsg");
	$msg->link_to_path($obj->{root}."/out");
}

################
# importing rules
sub remove_msg {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/allmsg");
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/sent");
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/newmsg");
	$msg->unlink_at_path($obj->{root}."/out");
}


sub import_qsp {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here

	# TODO: not working, implementing lookup via sha256 hashes first
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/qsprcvd");
	my @newmsgs=$obj->scan_dir(
		$obj->{root}."/call/".$obj->call2fname($msg->to)."/newmsg",
		"msg_([a-z]|[0-9]|\/)+_".$msg->msg_checksum.".xml"
	);
	foreach my $newmsg (@newmsgs) {
		unlink($newmsg) or die "removing of transmitted message failed"; 
	}
	$msg->link_to_path($obj->{root}."/out");
}
################
# importing rules
sub remove_qsp {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/qsprcvd");
	$msg->unlink_at_path($obj->{root}."/out");
}


sub import_pubkey {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here
	
	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call."/pubkey");
	$msg->link_to_path($obj->{root}."/out");
}
sub remove_pubkey {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call."/pubkey");
	$msg->unlink_at_path($obj->{root}."/out");
}

sub import_revoke {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here

	my @qtcmsgs=$obj->scan_dir(
		$obj->{root}."/out",
		".+_".$obj->call2fname($msg->call)."_.+.xml"
	);
	foreach my $filename (@qtcmsgs) {
		my $qtcmsg=qtc::msg->new(
			path=>$obj->{root}."/out",
			filename=>$filename, 
		);
		if ( $msg->type eq "msg" ) { 
			$obj->remove_msg($qtcmsg); 
			return; 
		}
		if ( $msg->type eq "qsp" ) { 
			$obj->remove_qsp($qtcmsg); 
			return; 
		}
		if ( $msg->type eq "operator" ) { 
			$obj->remove_operator($qtcmsg); 
			return; 
		}
		if ( $msg->type eq "pubkey" ) { 
			$obj->remove_pubkey($qtcmsg); 
			return; 
		}
		if ( $msg->type eq "revoke" ) { 
			$obj->remove_revoke($qtcmsg); 
			return; 
		}
		if ( $msg->type eq "trust" ) { 
			$obj->remove_trust($qtcmsg); 
			return; 
		}
	}
	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call."/revoke");
	$msg->link_to_path($obj->{root}."/out");
}

# normally this is not called.... i think 
sub remove_revoke {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call."/revoke");
	$msg->unlink_at_path($obj->{root}."/out");
}

sub import_operator {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here

	# TODO: place aliassing code here
	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call);

	foreach my $alias (split(/ /, $msg->set_of_aliases)) {
		#TODO link aliases 
	}
	
	foreach my $list (split(/ /, $msg->set_of_lists)) {
		$msg->link_to_path($obj->{root}."/lists/".$obj->call2fname($list));
	}
	
	$msg->link_to_path($obj->{root}."/out");
}
sub remove_operator {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call);
	$msg->unlink_at_path($obj->{root}."/out");
}

sub import_trust {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here

	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call."/trust");

	$msg->link_to_path($obj->{root}."/out");
}
sub remove_trust {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call."/trust");
	$msg->unlink_at_path($obj->{root}."/out");
}

sub is_message_new {
	my $obj=shift;
	my $msg=shift; 
	
	if ( $msg->type ne "msg" ) { die "Message must be type message\n"; }

}

1; 
