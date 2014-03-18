package qtc::processor; 
use qtc::msg; 
use File::Basename; 
use qtc::misc;
@ISA=(qtc::misc);

# this package does all the linking of a qtc-net message to its right folders 
########################################################
# obviously generic right now
########################################################
sub new { 
   my $class=shift; 
   my %parm=(@_); 
   my $obj=bless \%parm, $class; 
	if ( -d $obj->{root} ) { 
		die "I need a root folder to run the processor\n"; 
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
sub process_in { 
	my $obj=shift; 
	my $file=shift; 
	
	$msg=qtc::msg->new(
		xml=>$xml,
		path=>$obj->{root}."/in"
	); 
	$obj->process($msg); 
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
	
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/newmsg");
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/allmsg");
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/sent");
	
	$msg->link_to_path($obj->{root}."/out");
}

sub import_pubkey {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here
	
	$msg->link_to_path($obj->{root}."/call/".$msg->call."/pubkey");
	
	$msg->link_to_path($obj->{root}."/out");
}

sub import_revoke {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here

	# TODO: Place Key revokation code here

	$msg->link_to_path($obj->{root}."/call/".$msg->call."/revoke");
	$msg->link_to_path($obj->{root}."/out");
}

sub import_qtc {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here

	# TODO: not working, implementing lookup via sha256 hashes first
	
	$msg->link_to_path($obj->{root}."/call/".$msg->signature."/newmsg");
	$msg->link_to_path($obj->{root}."/call/".$msg->from."/allmsg");
	$msg->link_to_path($obj->{root}."/call/".$msg->from."/sent");
	
	$msg->link_to_path($obj->{root}."/out");
}

sub import_operator {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here

	# TODO: place aliassing code here

	$msg->link_to_path($obj->{root}."/call/".$msg->call);

	foreach my $alias (split(/ /, $msg->set_of_aliases)) {
		# TODO:Symlink directorys 
	}
	
	foreach my $list (split(/ /, $msg->set_of_lists)) {
		# TODO:Symlink directorys 
		$msg->link_to_path($obj->{root}."/lists/".$list);
	}
	
	$msg->link_to_path($obj->{root}."/out");
}

sub import_trust {
	my $obj=shift; 
	my $msg=shift; 
	# TODO: Place signature verification call here

	$msg->link_to_path($obj->{root}."/call/".$msg->call."/trust");

	$msg->link_to_path($obj->{root}."/out");
}

1; 
