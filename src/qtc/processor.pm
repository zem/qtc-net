package qtc::processor; 
use qtc::msg; 
use qtc::query; 
use File::Basename; 
use qtc::signature; 
use qtc::keyring; 
use Data::Dumper; 
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

sub query {
	my $obj=shift; 
	if ( ! $obj->{query} ) { 
		$obj->{query}=qtc::query->new(path=>$obj->{root}); 
	}
	return $obj->{query};
}	

sub keyring {
	my $obj=shift;
	my $msg=shift;
	my $call=$msg->call; 
	my @keys;  

	# we may have a public key here that we should handle at generation
	if ( $msg->type eq "pubkey" ) {
		#print STDERR "adding ".$msg->checksum." to keys\n"; 
		push @keys, $msg; 
	}
	
	if ( ! $call ) { die "I need a call to get a keyring for\n"; }

	if ( ! $obj->{keyring}->{$call} ) { 
		$obj->{keyring}->{$call}=qtc::keyring->new(
			call=>$call,
			root=>$obj->{root},
			keys=>\@keys, 
		);
	}
	#print STDERR " i am returning the ring now\n"; 
	return $obj->{keyring}->{$call};
}

sub keyring_clear {
	my $obj=shift; 
	my $call=shift; 

	delete $obj->{keyring}->{$call};
}

sub verify_signature {
	my $obj=shift; 
	my $msg=shift;
	
	my $keyhash=shift; 
	my $sig=qtc::signature->new(
		pubkey=>$obj->keyring($msg)->keyhash,
	);
	if (! $sig->verify($msg->signed_content_bin, $msg->signature, $msg->signature_key_id) ) { 
		die "Signature verification for message ".$msg->checksum." failed\n"; 
	}
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
	$obj->ensure_path($obj->{root}."/bad"); 
	$obj->ensure_path($obj->{root}."/in"); 

	foreach my $file ($obj->scan_dir($obj->{root}."/in", '.*\.qtc')){
		if (( ! -e $obj->{root}."/out/".$file ) and ( ! -e $obj->{root}."/bad/".$file )) { 
			print STDERR "processing file $file\n"; 
			eval { 
				$msg=qtc::msg->new(
					filename=>$file, 
					path=>$obj->{root}."/in",
				); 
				$obj->process($msg);
			};
			if ( $@ ) { 
				# an error occured
				print STDERR $@; 
				link($obj->{root}."/in/".$file,  $obj->{root}."/bad/".$file) or die "yes really this link fail leads to death\n"; 

			}
		}
	} 
}

# this is to be used for any message that is in /in
sub process_in_loop { 
	my $obj=shift;
	$obj->ensure_path($obj->{root}."/bad"); 
	$obj->ensure_path($obj->{root}."/in"); 

	my $num=-1; 

	while (1) { 
		my @files=$obj->scan_dir($obj->{root}."/in", '.*\.qtc');
		if ( $#files != $num ) {
			$num=$#files; 
			# something changed, we have to process
			$obj->process_in(); 
		}
		sleep 20; 
	}
}

sub process_hex { 
	my $obj=shift; 
	my $hex=shift; 
	
	$msg=qtc::msg->new(
		hex=>$hex,
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
	
	if ( $msg->type eq "telegram" ) { 
		$obj->import_telegram($msg); 
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
sub import_telegram {
	my $obj=shift; 
	my $msg=shift; 

	$obj->verify_signature($msg);
	
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/all");
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/telegrams/sent");
	if ( $obj->msg_has_no_qsp($msg) ) {
		$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/new");
	}
	$msg->link_to_path($obj->{root}."/out");
	
	my $listpath=$obj->{root}."/lists/".$obj->call2fname($msg->to);
	foreach my $list ($obj->scan_dir($listpath, ".+")) {
		if ( -l $listpath."/".$list ) { 
			# TODO Fix this 
			$msg->link_to_path($listpath."/".$list."/telegrams/all");
			if ( $obj->msg_has_no_qsp($msg, $list) ) {
				$msg->link_to_path($listpath."/".$list."/telegrams/new");
			}
		}
	}
}

################
# importing rules
sub remove_telegram {
	my $obj=shift; 
	my $msg=shift; 
	
	my $listpath=$obj->{root}."/lists/".$obj->call2fname($msg->to);
	foreach my $list ($obj->scan_dir($listpath, ".+")) {
		if ( -l $listpath."/".$list ) { 
			$msg->unlink_at_path($listpath."/".$list."/telegrams/all");
			$msg->unlink_at_path($listpath."/".$list."/telegrams/new");
		}
	}
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/all");
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/telegrams/sent");
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/new");
	$msg->unlink_at_path($obj->{root}."/out");
}

sub msg_has_no_qsp {
	my $obj=shift; 
	my $msg=shift; 
	my $f_to=shift; 

	if ( ! $f_to ) { 
		$f_to=$obj->call2fname($msg->to);
	}
	
	$obj->ensure_path($obj->{root}."/call/".$f_to."/qsprcvd"); 
	my @files=$obj->scan_dir(
		$obj->{root}."/call/".$f_to."/qsprcvd",
		'qsp_([a-z]|[0-9]|-)+_([0-9]|[a-f])+\.qtc'
	);
	foreach my $file (@files) {
		my $qsp=qtc::msg->new(
			path=>$obj->{root}."/call/".$f_to."/qsprcvd",
			filename=>$file,
		); 
		#print "Compare ".$qsp->telegram_checksum." and ".$msg->checksum."\n"; 
		if ($qsp->telegram_checksum eq $msg->checksum) { return 0; }
	}
	return 1; 
}


sub import_qsp {
	my $obj=shift; 
	my $msg=shift; 
	$obj->verify_signature($msg); 	

	# TODO: not working, implementing lookup via sha256 hashes first
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/qsprcvd");
	my @newmsgs=$obj->scan_dir(
		$obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/new",
		"telegram_([a-z]|[0-9]|-)+_".$msg->telegram_checksum.".qtc"
	);
	foreach my $newmsg (@newmsgs) {
		unlink($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/new/".$newmsg) or die "removing of transmitted message $newmsg failed"; 
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
	$obj->verify_signature($msg);	
	
	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call."/pubkey");
	$msg->link_to_path($obj->{root}."/out");

	# keyring cache must be cleared now 
	$obj->keyring_clear($msg->call); 

	# last but not least if we came that far we need to get any bad message for this 
	# call for reprocessing
	my @badmsgs=$obj->scan_dir(
		$obj->{root}."/bad",
		".+_".$msg->escaped_call."_([0-9]|[a-f])+.qtc"
	);
	foreach my $badmsg (@badmsgs) {
		unlink($obj->{root}."/bad/".$badmsg) or die "can't unlink bad message $badmsg for reprocessing\n"; 
	}
	
}
sub remove_pubkey {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call."/pubkey");
	$msg->unlink_at_path($obj->{root}."/out");
	
	# keyring cache must be cleared now 
	$obj->keyring_clear($msg->call); 
}

sub remove_msg { 
	my $obj=shift; 
	my $msg=shift; 
	if ( $msg->type eq "telegram" ) { 
		$obj->remove_telegram($msg); 
		print "returning remove telegram\n";
		return; 
	}
	if ( $msg->type eq "qsp" ) { 
		$obj->remove_qsp($msg); 
		return; 
	}
	if ( $msg->type eq "operator" ) { 
		$obj->remove_operator($msg); 
		return; 
	}
	if ( $msg->type eq "pubkey" ) { 
		$obj->remove_pubkey($msg); 
		return; 
	}
	if ( $msg->type eq "revoke" ) { 
		$obj->remove_revoke($msg); 
		return; 
	}
	if ( $msg->type eq "trust" ) { 
		$obj->remove_trust($msg); 
		return; 
	}
	print $msg->type."is an unknown message type \n"; 
}

sub import_revoke {
	my $obj=shift; 
	my $msg=shift; 
	$obj->verify_signature($msg);	

	my @qtcmsgs=$obj->scan_dir(
		$obj->{root}."/out",
		".+_".$obj->call2fname($msg->call)."_.+.qtc"
	);
	foreach my $filename (@qtcmsgs) {
		my $qtcmsg=qtc::msg->new(
			path=>$obj->{root}."/out",
			filename=>$filename, 
		);
		$obj->remove_msg($qtcmsg); 
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

sub remove_msgs_below {
	my $obj=shift; 
	my $path=shift; 
	my %args=(@_);
	my @entrys=$obj->scan_dir(
		$path,
		".+"
	);
	foreach my $entry (@entrys) {
		my $absentry=$path."/".$entry;
		if ( -d $absentry ) {
			# remove_msgs_below 
			$obj->remove_msgs_below($absentry, %args);
			if ( $args{mrproper} ) {
				rmdir($absentry) or die "can't unlink direcrory ".$absentry."\n"; 
			}
		} elsif ( -l $absentry ) {
			if ( $args{mrproper} ) {
				unlink($absentry) or die "can't unlink link ".$absentry."\n"; 
			}
		} elsif ( -f $absentry ) {
			my $msg=qtc::msg->new(path=>$path, filename=>$entry); 
			$obj->remove_msg($msg); 
		}
	}
}

sub import_operator {
	my $obj=shift; 
	my $msg=shift; 
	$obj->verify_signature($msg);	

	my $oldop=$obj->query->operator($msg->call); 
	if ( $oldop ) { 
		if ( $oldop->record_date >= $msg->record_date ) { 
			die "there is an old operator message newer than this one skip this\n"; 
		}
		$obj->remove_operator($oldop); 
	}
	
	foreach my $alias ($msg->set_of_aliases) {
		my $f_alias=$obj->call2fname($alias); 
		if ( -l $obj->{root}."/call/$f_alias" ) {
			# make sure we are the owners
			unlink($obj->{root}."/call/$f_alias") or die "we cant unlink a linked dir to ensure ownership\n"; 
			symlink($msg->escaped_call, $obj->{root}."/call/$f_alias") or die "1 failed to link to $f_alias\n"; 
		} elsif ( -d $obj->{root}."/call/$f_alias" ) {
			my $otherop=$obj->query->operator($alias);
			if ( ! $otherop ) {
				# the directory is empty lets takeover
				$obj->remove_msgs_below($obj->{root}."/call/$f_alias", mrproper=>1);
				rmdir($obj->{root}."/call/$f_alias") or die "failed to unlink $f_alias\n"; 
				symlink($msg->escaped_call, $obj->{root}."/call/$f_alias") or die "2 failed to link to $f_alias\n"; 
			} 
		} else {
			symlink($msg->escaped_call, $obj->{root}."/call/$f_alias") or die "3 failed to link to $f_alias\n"; 
		}
	}
	
	foreach my $list ($msg->set_of_lists) {
		my $abs_link=$obj->{root}."/lists/".$obj->call2fname($list)."/".$msg->escaped_call;
		if ( ! -e $abs_link ) {
			$obj->ensure_path($obj->{root}."/lists/".$obj->call2fname($list)); 
			symlink("../../call/".$msg->escaped_call, $abs_link) or die "4 failed to link to list \n"; 
		}
	}
	
	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call);
	$msg->link_to_path($obj->{root}."/out");
}

sub remove_operator {
	my $obj=shift; 
	my $msg=shift; 
	
	# remove list entrys
	foreach my $alias ($msg->set_of_aliases) {
		my $f_alias=$obj->call2fname($alias); 
		if ( -l $obj->{root}."/call/$f_alias" ) {
			# yes it is stupid to think that this link points to 
			# our directory TODO: Check that in the future
			unlink($obj->{root}."/call/$f_alias") or die "cant unlink our sylinked $f_alias\n";
		}
	}
	
	# remove alias entrys 
	foreach my $list ($msg->set_of_lists) {
		my $abs_link=$obj->{root}."/lists/".$obj->call2fname($list)."/".$msg->escaped_call;
		if ( -l $abs_link ) {
			# the next foreach removes all messages that where sent via a list to this user
			# this is because the message will not remove itself when the link is gone
			foreach my $file ($obj->scan_dir($abs_link."/telegrams/all", "telegram.+.qtc")) {
				my $telegram=qtc::msg->new(path=>$abs_link."/telegrams/all", filename=>$file); 
				if ( $telegram->to eq $list) { 
					$obj->remove_msg($msg); 
				}
			}
			unlink($abs_link) or die "cant unlink $abs_link\n"; 
		}
	}
	
	# TODO Operator removal
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call);
	$msg->unlink_at_path($obj->{root}."/out");
}

sub import_trust {
	my $obj=shift; 
	my $msg=shift; 
	$obj->verify_signature($msg);	

	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call."/trust");

	$msg->link_to_path($obj->{root}."/out");
}
sub remove_trust {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call."/trust");
	$msg->unlink_at_path($obj->{root}."/out");
}

1; 
