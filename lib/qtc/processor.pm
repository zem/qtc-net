#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::processor - class that sorts qtc messages 

=head1 SYNOPSIS

use qtc::processor;

my $processor=qtc::processor->new(
   root=>$path,
   log=>$log, 
   daemon=>$daemon, 
); 
$processor->process_in_loop; 

=head1 DESCRIPTION

The QTC Processor is responsible for sorting all QTC Messages 
from /in to the filesystem structure as described in protocol.txt

It may run as daemon, and it will look for qtc messages every 60 seconds. 
However an application may send a HUP signal which causes the processor 
to wake up immidiately. 

Each message type has its own import() method as well as its own 
remove() method.  If a message needs some reprocessing it will removed 
from the tree which causes the processor to sort it back in during its 
next run. 

because many of the methods and librarys will die on failure, the processor also 
implements some exception handling during the process loop (this is called eval {} 
in perl)

=cut
#-----------------------------------------------------------------------------------
package qtc::processor; 
use qtc::msg; 
use qtc::query; 
use IO::Handle;
use File::Basename; 
use File::ExtAttr; 
use qtc::signature; 
use qtc::keyring; 
use Data::Dumper; 
use qtc::misc;
@ISA=(qtc::misc);

#------------------------------------------------------------------------------------
=pod

=head2 new(parameter=>"value", ...)

Optional parameters: 
root=>$path_to_dir_structure
pidfile=>$pid_filename #default: $path_to_dir_structure/.qtc_processor.pid
log=>$logfile
daemon=>1, # means daemonize 

Returns: a qtc::processor object

This creates a processor object. 

=cut
#------------------------------------------------------------------------------------
sub new { 
   my $class=shift; 
   my %parm=(@_); 
   my $obj=bless \%parm, $class; 
	if ( ! $obj->{root} ) { 
		$obj->{root}=$ENV{HOME}."/.qtc"; 
	}
	if ( $obj->{daemon} ) {
		# deamonize
		my $pid=fork(); 
		if ( $pid != 0 ) { exit; }
	}
	if ( ! $obj->{pidfile} ) { 
		$obj->{pidfile}=$obj->{root}."/.qtc_processor.pid";
	}
	$obj->daemonize(); 
	if ( $obj->{log} ) { 
		close STDERR; 
		open(STDERR, ">> ".$obj->{log}) or die "can't open logfile ".$obj->{log}." \n";	
		STDERR->autoflush(1); 
	}
	if ( ! $obj->{qsp_timeout} ) {
		$obj->{qsp_timeout}=8640000;  # should be abt 100 days not exactly 
	} 

	# if ttl_timeout is changed the server should act as an archive, never pushing 
	# actively to the network...... 
	if ( ! $obj->{ttl_timeout} ) {
		$obj->{ttl_timeout}=86400*200;  # we don't need to distribute messages older 200 days
	} 
	if ( ! $obj->{archive_timeout} ) {
		$obj->{archive_timeout}=86400*200;  
		# we will move a message that is longer that 200 days in old to the archive
	} 
	# for reference, this setting tells the processor to move all old 
	# messages to archive. 
	if ( ! $obj->{archive} ) {
		$obj->{archive}=0;  
	} 

   return $obj; 
}

#------------------------------------------------------------------------------------
=pod

=head2 DESTROY()

if the process runs as daemon, unlink the pid file on exit 

=cut
#------------------------------------------------------------------------------------
sub DESTROY {
	my $o=shift; 
	if ( $o->{daemonized} ) {
		unlink($o->{pidfile}); 
	}
}

#------------------------------------------------------------------------------------
=pod

=head2 query()

Returns a fully initialized qtc::query object, for querys on the 
QTC filesystem tree.  

=cut
#------------------------------------------------------------------------------------
sub query {
	my $obj=shift; 
	if ( ! $obj->{query} ) { 
		$obj->{query}=qtc::query->new(path=>$obj->{root}); 
	}
	return $obj->{query};
}	

#------------------------------------------------------------------------------------
=pod

=head2 keyring($msg)

This returns a qtc::keyring object for the call that published the 
message $msg, if the message is a public key, it is put into the keyring as well. 
we could not validate a self signed public key. 

if there is anything strange with that injected message qtc::keyring will handle. 

=cut
#------------------------------------------------------------------------------------
sub keyring {
	my $obj=shift;
	my $msg=shift;
	my $call=$msg->call; 
	my @keys;  

	# we may have a public key here that we should handle at generation
	if ( $msg->type eq "pubkey" ) {
		#print STDERR $obj->ts_str." adding ".$msg->checksum." to keys\n"; 
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
	#print STDERR $obj->ts_str." i am returning the ring now\n"; 
	return $obj->{keyring}->{$call};
}

#------------------------------------------------------------------------------------
=pod

=head2 keyring_clear($call)

This clears the keyring cache for a specific call, for example after a revoke. 

=cut
#------------------------------------------------------------------------------------
sub keyring_clear {
	my $obj=shift; 
	my $call=shift; 

	delete $obj->{keyring}->{$call};
}

#------------------------------------------------------------------------------------
=pod

=head2 verify_signature($msg)

This verifies the signature of a message. It will cause death if verification 
fails. That exception can then be handled, in process_in(). 

=cut
#------------------------------------------------------------------------------------
sub verify_signature {
	my $obj=shift; 
	my $msg=shift;

	my $keyhash=shift; 
	if ( ! $keyhash ) {  
		$keyhash=$obj->keyring($msg)->keyhash; 
	}
	my $sig=qtc::signature->new(
		pubkey=>$keyhash,
	);
	if (! $sig->verify($msg->signed_content_bin, $msg->signature, $msg->signature_key_id) ) { 
		die "Signature verification for message ".$msg->checksum." failed\n"; 
	}
}


#------------------------------------------------------------------------------------
=pod

=head2 process_file($file)

This loads the *.qtc file given by $file into a qtc::msg object 
it then links the message to /in and starts processing of that message.

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 process_one_msg_from_in($file_basename)

This starts file processing of a file that is in /in
note that only the files basename is needed as argument. 

=cut
#------------------------------------------------------------------------------------
sub process_one_msg_from_in { 
	my $obj=shift; 
	my $file=shift; 

	$msg=qtc::msg->new(
		filename=>$file, 
		path=>$obj->{root}."/in",
	); 
	$obj->process($msg);
}

#------------------------------------------------------------------------------------
=pod

=head2 process_in()

This starts a process run for all unprocessed, new 
messages in /in

That means every message that is in in but not in either 
/out or /bad needs some processing. So it is loaded 
and the resulting object is given to the process() mehthod. 

Exeption handling is also done here. If process() dies the 
message will be linked to /bad

=cut
#------------------------------------------------------------------------------------
sub process_in { 
	my $obj=shift;
	$obj->ensure_path($obj->{root}."/bad"); 
	$obj->ensure_path($obj->{root}."/in"); 

	my $cnt=0; 
	foreach my $file ($obj->scan_dir($obj->{root}."/in", '.*\.qtc$')){
		# this tweak handles a telegram messages qsptime 
		if (
			( -e $obj->{root}."/out/".$file ) 
			and ( $file =~ /^telegram_/ )
			and ( ! -e $obj->{root}."/bad/".$file )
			and ( ! -e $obj->{root}."/old/".$file )
			and ( ! -e $obj->{root}."/archive/".$file )
		) {
			$obj->chk_qsptime_on_telegram($file);
		}	
		if (
			( -e $obj->{root}."/out/".$file ) 
			and ( ! -e $obj->{root}."/bad/".$file )
			and ( ! -e $obj->{root}."/old/".$file )
			and ( ! -e $obj->{root}."/archive/".$file )
		) {
			$obj->chk_ttl_timeout($file);
		}	
		if (
			( ! -e $obj->{root}."/out/".$file ) 
			and (
				( -e $obj->{root}."/bad/".$file )
				or ( -e $obj->{root}."/old/".$file )
			)
			and ( ! -e $obj->{root}."/archive/".$file )
		) {
			$obj->chk_archive_timeout($file);
		}	
		# if a message is new.....
		if (
			( ! -e $obj->{root}."/out/".$file ) 
			and ( ! -e $obj->{root}."/bad/".$file )
			and ( ! -e $obj->{root}."/old/".$file )
			and ( ! -e $obj->{root}."/archive/".$file )
		) { 
			$cnt++;
			print STDERR $obj->ts_str." processing file $file\n"; 
			eval { 
				$msg=qtc::msg->new(
					filename=>$file, 
					path=>$obj->{root}."/in",
				); 
				$obj->process($msg);
			};
			if ( $@ ) { 
				# an error occured
				print STDERR $obj->ts_str." ".$@; 
				link($obj->{root}."/in/".$file,  $obj->{root}."/bad/".$file) or die "yes really this link fail leads to death\n"; 
			}
		} 
	} 
	return $cnt; 
}

#------------------------------------------------------------------------------------
=pod

=head2 process_in_loop()

This calls process_in() in a loop. it will sleep for 60 seconds and then look for new 
messages in /in. If the process receives a HUP signal it will wake up immidiately. 

=cut
#------------------------------------------------------------------------------------
sub process_in_loop { 
	my $obj=shift;
	$obj->ensure_path($obj->{root}."/archive"); 
	$obj->ensure_path($obj->{root}."/old"); 
	$obj->ensure_path($obj->{root}."/bad"); 
	$obj->ensure_path($obj->{root}."/in"); 

	my $num=-1; 

	$SIG{HUP}=sub {}; # we dont want sighup to kill us 

	while (1) { 
		my @files=$obj->scan_dir($obj->{root}."/in", '.*\.qtc');
		#print STDERR "there are ".($#files+1)." of $num files to process is that changed?\n"; 
		if ( $#files != $num ) {
			$num=$#files; 
			# something changed, we have to process
			while ($obj->process_in()) { print STDERR $obj->ts_str." There may be more files, try another time\n" }
		}
		eval {
			local $SIG{HUP}=sub { die "hup rcvd"; };
			sleep 60;
		}; 
		if ( $@ ) { 
			die $@ unless $@ =~ /^hup rcvd/;
			print STDERR $obj->ts_str." Got a hup signal, will wake up immidiately\n"; 
		} 
	}
}

#------------------------------------------------------------------------------------
=pod

=head2 process_hex($hex_msg)

This will process a message that is given as hexadecimal string argument

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 write_msg_to_in($msg)

This writes a message to in, with a bit of precaution, if the message already 
exist, it will die() before it trys. 

=cut
#------------------------------------------------------------------------------------
sub write_msg_to_in {
	my $obj=shift; 
	my $msg=shift; 

	if ( -e $obj->{root}."/in/".$msg->filename ) { 
		die "ups this object ".$msg->filename." already exist in $obj->{root}/in \n" 
	}
	$msg->to_filesystem($obj->{root}."/in");
}

#------------------------------------------------------------------------------------
=pod

=head2 process($msg)

This sorts $msg into the folder structure. 
basically it calls the right import_...() method for each 
message type that does the job.  

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 chk timestamp methods


=cut
#------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------
=pod

=head3 chk_qsptime_on_telegram($filename)

This method checks if the QSP time for a telegram is reached and triggers 
a delivery even if there is no qsp, if so. 

=cut
#------------------------------------------------------------------------------------
sub chk_qsptime_on_telegram {
	my $obj=shift; 
	my $file=shift; 

	my $qsptime=getfattr(
		$obj->{root}."/in/".$file,
		"qsptime"
	);
	my $qsp_delivered=getfattr(
		$obj->{root}."/in/".$file,
		"qsp"
	);

	if ( ! $qsptime ) {
		print STDERR "Message $file does not have a qsptime attr\n";  
		return; 
	}
	if (( $qsptime < time ) and ( ! $qsp_delivered)) {
		# because we had already read this telegram when we set 
		# the $qsptime we know that this works
		my $msg=qtc::msg->new(
			filename=>$file, 
			path=>$obj->{root}."/in",
		); 
		$obj->qsp_telegram($msg->to, $msg->checksum, "timeout"); 
	}
}

#------------------------------------------------------------------------------------
=pod

=head3 chk_ttl_timeout($filename)

This method checks if the ttl timeout for a message is reached. 
It triggers a message remove and a move to the /old directory if so. 

=cut
#------------------------------------------------------------------------------------
sub chk_ttl_timeout {
	my $obj=shift; 
	my $file=shift; 

	my $btime=getfattr(
		$obj->{root}."/in/".$file,
		"btime"
	);

	if ( ! $btime ) {
		print STDERR "Message $file does not have a btime attr\n";  
		return; 
	}

	if ( $btime+$obj->{ttl_timeout} < time ) { 
		if (
			( $file =~ /(^(pubkey_)|(trust_)|(operator_)|(revoke_)/ )
			and ( -e $obj->{root}."/out/".$file ) 
		) {
			# these messages need to stick longer if they are still in out
			# NOP 
		} else {
			my $msg=qtc::msg->new(
				filename=>$file, 
				path=>$obj->{root}."/in",
			); 
			$msg->link_to_path($obj->{root}."/old");
			setfattr(
				$obj->{root}."/in/".$msg->filename,
				"ttltime",
				time
			);
			if ( $msg->type eq "telegram" ) { 
				$obj->remove_telegram($msg); 
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
				# should never be made
				$obj->remove_revoke($msg); 
				return; 
			}
			if ( $msg->type eq "trust" ) { 
				$obj->remove_trust($msg); 
				return; 
			}				
		}
	} 
}

#------------------------------------------------------------------------------------
=pod

=head3 chk_archive_timeout($filename)

This method checks if the archive timeout for a message is reached. 
it either removes the message from the directorys or it will moves 
them to /archive if needed 

=cut
#------------------------------------------------------------------------------------
sub chk_archive_timeout {
	my $obj=shift; 
	my $file=shift; 
	my $badmessage=0; 

	my $ttltime=getfattr(
		$obj->{root}."/in/".$file,
		"ttltime"
	);

	if ( ! $ttltime ) {
		if ( -e $obj->{root}."/bad/".$file ) {
			$badmessage=1; 
			# this is a bad message, use either mtime or btime
			$ttltime=getfattr(
				$obj->{root}."/in/".$file,
				"btime"
			);
			if ( ! $ttltime ) { $ttltime=(stat($obj->{root}."/in/".$file))[9]; }
			if ( ! $ttltime ) { 
				print STDERR "Message $file does not have a ttltime attr and we could not stat a suitable time\n";  
				return; 
			}
	}

	if ( $ttltime+$obj->{archive_timeout} < time ) { 
		if ( $obj->{archive} ) { 
			link($obj->{root}."/in/".$file, $obj->{root}."/archive/".$file) or die "can't link to archive directory\n";
		}
		unlink($obj->{root}."/in/".$file); 
		if ( $badmessage ) {
			unlink($obj->{root}."/bad/".$file); 
		} else {
			unlink($obj->{root}."/old/".$file);
		} 
	}
}

#------------------------------------------------------------------------------------
=pod

=head2 import and remove methods


=cut
#------------------------------------------------------------------------------------


#------------------------------------------------------------------------------------
=pod

=head3 import_telegram($msg)

This imports a telegram message to the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub import_telegram {
	my $obj=shift; 
	my $msg=shift; 

	$obj->verify_signature($msg);

	# this calculates the qsptime timestamp and sets it as user attribute
	my $qsptime=$obj->{qsp_timeout};
	if ( $msg->set_of_qsp_timeout ) {
		$qsptime=$msg->btime+($msg->set_of_qsp_timeout)[0];
	}
	setfattr(
		$obj->{root}."/in/".$msg->filename,
		"qsptime", 
		$qsptime
	);
	# if there is any qsp attribute, delete it, we may have the rare 
	# event that we have to reimport a telegram 
	delfattr(
		$obj->{root}."/in/".$msg->filename,
		"qsp", 
	);

	#############################
	# this block calculates if a message with multiple checksums is to be propagated, oldest wins. 
	if ( $msg->checksum_period ) { 
		# if this message has a checksum period we need to find out if there already is a message
		# the oldest message counts 
		foreach my $chk ($msg->checksum, $msg->prev_checksum, $msg->next_checksum) {
			my $other=$obj->query->telegram_by_checksum($chk); 
			if ( ! $other ) { next; } 
			if ( $other->telegram_date < $msg->telegram_date ) { 
				$msg->link_to_path($obj->{root}."/old");
				setfattr(
					$obj->{root}."/in/".$msg->filename,
					"ttltime",
					time
				);
				setfattr(
					$obj->{root}."/in/".$msg->filename,
					"identical_with",
					"$other->checksum"
				);
				return; 
			}
			if ( $other->telegram_date > $msg->telegram_date ) { 
				$obj->remove_telegram($other); 
				last; 
			}
			if ( $other->telegram_date == $msg->telegram_date ) {
				# ok lets have a look at the checksum...
				if ( $obj->checksum_is_t($other->signature_checksum, $msg->signature_checksum) ) {
					$obj->remove_telegram($other); 
					last; 
				} else {
					$msg->link_to_path($obj->{root}."/old");
					return; 
				}
			}	
		}
	}
	
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/all");
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/telegrams/sent");
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/timeline");
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/telegrams/timeline");
	if ( $obj->msg_has_no_qsp($msg) ) {
		$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/new");
		$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/timeline_new");
	}
	$msg->link_to_path($obj->{root}."/out");
	
	# mailing following handling 
	my $followingpath=$obj->{root}."/followings/".$obj->call2fname($msg->to);
	foreach my $followingmember ($obj->scan_dir($followingpath, ".+")) {
		if ( -l $followingpath."/".$followingmember ) { 
			# if one of the followingmembers has sent this message to the following, he does not need it. 
			if ( $obj->call2fname($msg->to) eq $followingmember ) { next; }
			$msg->link_to_path($followingpath."/".$followingmember."/telegrams/all");
			$msg->link_to_path($followingpath."/".$followingmember."/telegrams/timeline");
			if ( $obj->msg_has_no_qsp($msg, $followingmember) ) {
				#$msg->link_to_path($followingpath."/".$followingmember."/telegrams/new");
				$msg->link_to_path($followingpath."/".$followingmember."/telegrams/timeline_new");
			}
		}
	}
}

#------------------------------------------------------------------------------------
=pod

=head3 remove_telegram($msg)

This removes a telegram from the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub remove_telegram {
	my $obj=shift; 
	my $msg=shift; 
	
	my $followingpath=$obj->{root}."/followings/".$obj->call2fname($msg->to);
	foreach my $following ($obj->scan_dir($followingpath, ".+")) {
		if ( -l $followingpath."/".$following ) { 
			$msg->unlink_at_path($followingpath."/".$following."/telegrams/all");
			$msg->unlink_at_path($followingpath."/".$following."/telegrams/timeline");
			$msg->unlink_at_path($followingpath."/".$following."/telegrams/timeline_new");
		}
	}
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/all");
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/telegrams/sent");

	# removal from the timeline directorys 
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/telegrams/timeline");
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/timeline");
	# from telegram_timeline_new should not be needed here. 
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->from)."/telegrams/timeline_new");
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/timeline_new");

	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/telegrams/new");
	$msg->unlink_at_path($obj->{root}."/out");
}

#------------------------------------------------------------------------------------
=pod

=head3 msg_has_no_qsp($msg)

alternative msg_has_no_qsp($msg, $f_to)

checks if a message is not yet delivered. It could happen in big networks that the 
delivery notification was imported before the message was, in that case a message should 
not me linked to new messages. 

an optional filename_to parameter set the to for the case that the message was delivered 
to a following. $f_to must be filesystem compliat (see call2fname() for that). If not set, 
$obj->call2fname($msg->to) is used. 

The method returns 0  if msg has a qsp and 1 on success if msg has no qsp.

=cut
#------------------------------------------------------------------------------------
sub msg_has_no_qsp {
	my $obj=shift; 
	my $msg=shift; 
	my $f_to=shift; 

	if ( ! $f_to ) { 
		$f_to=$obj->call2fname($msg->to);
	}

	# this block checks if the message was sent to self
	my $to=$obj->fname2call($f_to);
	if ( $to eq $msg->from ) { return 0; }
	my $op=$obj->query->operator($to);
	if ( $op ) {
		foreach my $alias ($op->set_of_aliases) {
			if ( $msg->from eq $alias ) { return 0; }
		}
	}
	
	# ensure path should not be needed here
	#$obj->ensure_path($obj->{root}."/call/".$f_to."/qsp/".$msg->checksum); 
	my @files=$obj->scan_dir(
		$obj->{root}."/call/".$f_to."/qsp/".$msg->checksum,
		'qsp_([a-z]|[0-9]|-)+_([0-9]|[a-f])+\.qtc'
	);
	foreach my $file (@files) {
		#my $qsp=qtc::msg->new(
		#	path=>$obj->{root}."/call/".$f_to."/qsp/".$msg->checksum,
		#	filename=>$file,
		#); 
		##print "Compare ".$qsp->telegram_checksum." and ".$msg->checksum."\n"; 
		#if ($qsp->telegram_checksum eq $msg->checksum) { return 0; }
		return 0; # if there are any qsps there 
	}
	return 1; 
}

#------------------------------------------------------------------------------------
=pod

=head3 checksum_is_lt($chk1, $chk2)

compares two bigenatian hexadecimal numbers 
returns 1 if $chk1 < $chk2 and undef otherwise, 

=cut
#------------------------------------------------------------------------------------
sub chksum_is_lt {
	my $obj=shift;
	my $chk1=shift; 
	my $chk2=shift; 
	
	while ( $chk1 ) {
		my $t1=unpack("I>*", pack("H*", substr($chk1, 0, 2))); 
		my $t2=unpack("I>*", pack("H*", substr($chk2, 0, 2))); 
		if ( $t1 > $t2 ) { return; }
		$chk1=substr($chk1, 2); 
		$chk2=substr($chk2, 2); 
	}
	return 1; 
}


#------------------------------------------------------------------------------------
=pod

=head3 qsp_telegram($to, $checksum, $comment)

this method will qsp a telegram to a person with some checksum, it is called 
either from import_qsp() or from qsp_timeout(). the string comment is placed into 
the extended attribute of the telegram file

=cut
#------------------------------------------------------------------------------------
sub qsp_telegram {
	my $obj=shift; 
	my $to=shift; 
	my $checksum=shift; 
	my $comment=shift; 

	my @newmsgs=$obj->scan_dir(
		$obj->{root}."/call/".$obj->call2fname($to)."/telegrams/new",
		"telegram_([a-z]|[0-9]|-)+_".$checksum.".qtc"
	);
	foreach my $newmsg (@newmsgs) {
		# set qsp comment see also next foreach with the "same" code
		if ( $comment ) {
			setfattr(
				$obj->{root}."/in/".$newmsg,
				"qsp", 
				$comment
			);		
			$comment=""; 
		}
		unlink($obj->{root}."/call/".$obj->call2fname($to)."/telegrams/new/".$newmsg) or die "removing of transmitted message $newmsg failed"; 
	}
	# remove also telegrams from the timeline_new directory
	@newmsgs=$obj->scan_dir(
		$obj->{root}."/call/".$obj->call2fname($to)."/telegrams/timeline_new",
		"telegram_([a-z]|[0-9]|-)+_".$checksum.".qtc"
	);
	foreach my $newmsg (@newmsgs) {
		unlink($obj->{root}."/call/".$obj->call2fname($to)."/telegrams/timeline_new/".$newmsg) or die "removing of transmitted message $newmsg failed"; 
		# just to be sure that the comment is really set, it is a bit of spagetti mama mia 
		if ( $comment ) {
			setfattr(
				$obj->{root}."/in/".$newmsg,
				"qsp", 
				$comment
			);		
			$comment=""; 
		}
	}
}


#------------------------------------------------------------------------------------
=pod

=head3 import_qsp($msg)

This imports a qsp message to the filesystem structure. 
It also removes the delivered telegram from the following of new telegrams

=cut
#------------------------------------------------------------------------------------
sub import_qsp {
	my $obj=shift; 
	my $msg=shift; 
	$obj->verify_signature($msg); 	
	if ( $msg->checksum_period ) { die "I dont know how to deal with ".$msg->type." and checksum_period \n"; }

	# TODO: not working, implementing lookup via sha256 hashes first
	$msg->link_to_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/qsp/".$msg->telegram_checksum);
	$obj->qsp_telegram($msg->to, $msg->telegram_checksum, "qsp");
	$msg->link_to_path($obj->{root}."/out");
}


#------------------------------------------------------------------------------------
=pod

=head3 remove_qsp($msg)

This removes a qsp message from the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub remove_qsp {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$obj->call2fname($msg->to)."/qsp/".$msg->telegram_checksum);
	$msg->unlink_at_path($obj->{root}."/out");
}

#------------------------------------------------------------------------------------
=pod

=head3 import_pubkey($msg)

This imports a pubkey message to the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub import_pubkey {
	my $obj=shift; 
	my $msg=shift; 
	$obj->verify_signature($msg);	
	if ( $msg->checksum_period ) { die "I dont know how to deal with ".$msg->type." and checksum_period \n"; }
	
	print STDERR "Message Signature Check is done\n"; 
	
	# check if there are any revokes for this key
	my @revokes=$obj->scan_dir(
		$obj->{root}."/call/".$msg->escaped_call."/revoke",
		"revoke_([a-z]|[0-9]|-)+_[0-9a-f]+.qtc"
	);
	foreach my $revokefile (@revokes) {
		my $revoke=qtc::msg->new(
			path=>$obj->{root}."/call/".$msg->escaped_call."/revoke",
			filename=>$revokefile,
		); 
		if ( $msg->key_id eq $revoke->key_id ) {
			print STDERR "This key_id ".$msg->key_id." is revoked\n"; 
			$msg->link_to_path($obj->{root}."/old");			
			return; 
		}
	}
	
	print STDERR "check for revokes of this key passed\n"; 

	#this block removes old keys with the same signature from the repo
	my @oldversions=$obj->scan_dir(
		$obj->{root}."/call/".$msg->escaped_call."/pubkey",
		"pubkey_([a-z]|[0-9]|-)+_[0-9a-f]+.qtc"
	);
	foreach my $oldversion (@oldversions) {
		my $oldmsg=qtc::msg->new(
			path=>$obj->{root}."/call/".$msg->escaped_call."/pubkey",
			filename=>$oldversion,
		);
		if (
			( $msg->key_id eq $oldmsg->key_id ) 
			and 
			( $msg->signature_key_id eq $oldmsg->signature_key_id ) 
		) { 
			if ( $msg->key_date > $oldmsg->key_date ) {
				$obj->remove_pubkey($oldmsg);
			} else { 
				print STDERR "Key ".$msg->filename."is an old key, not importing\n"; 
				$msg->link_to_path($obj->{root}."/old");			
				return; 
			}
		}
	}
	
	print STDERR "older keyversions done\n"; 

	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call."/pubkey");
	$msg->link_to_path($obj->{root}."/out");

	print STDERR "key linked to target \n"; 

	# keyring cache must be cleared now 
	$obj->keyring_clear($msg->call); 

	# last but not least if we came that far we need to get any old message for this 
	# call for reprocessing
	my @badmsgs=$obj->scan_dir(
		$obj->{root}."/bad",
		".+_".$msg->escaped_call."_([0-9]|[a-f])+.qtc"
	);
	foreach my $badmsg (@badmsgs) {
		unlink($obj->{root}."/bad/".$badmsg) or die "can't unlink bad message $badmsg for reprocessing\n"; 
	}
	
}

#------------------------------------------------------------------------------------
=pod

=head3 remove_pubkey($msg)

This removes a pubkey message from the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub remove_pubkey {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call."/pubkey");
	$msg->unlink_at_path($obj->{root}."/out");
	
	# keyring cache must be cleared now 
	$obj->keyring_clear($msg->call); 
}


#------------------------------------------------------------------------------------
=pod

=head3 remove_msg($msg)

This removes any qtc message object from the filesystem structure 
by calling the right remove method.... 

=cut
#------------------------------------------------------------------------------------
sub remove_msg { 
	my $obj=shift; 
	my $msg=shift; 
	if ( $msg->type eq "telegram" ) { 
		$obj->remove_telegram($msg); 
		print STDERR $obj->ts_str." returning remove telegram\n";
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
	print STDERR $obj->ts_str." ".$msg->type."is an unknown message type \n"; 
}

#------------------------------------------------------------------------------------
=pod

=head3 import_revoke($msg)

This imports a revoke message to the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub import_revoke {
	my $obj=shift; 
	my $msg=shift; 
	my %keyhash; 
	$keyhash{$msg->key_id}=$msg; 
	$obj->verify_signature($msg,\%keyhash);	
	if ( $msg->checksum_period ) { die "I dont know how to deal with ".$msg->type." and checksum_period \n"; }

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

#------------------------------------------------------------------------------------
=pod

=head3 remove_revoke($msg)

This removes a revoke message from the filesystem structure.
It is here for completeness reasons, but normally it should never 
be used. 

=cut
#------------------------------------------------------------------------------------
# normally this is not called.... i think 
sub remove_revoke {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call."/revoke");
	$msg->unlink_at_path($obj->{root}."/out");
}

#------------------------------------------------------------------------------------
=pod

=head3 remove_msgs_below($path, argument=>"value", ...)

This removes all messages below a path, and its subdirectorys. 

parameters: 
    mrproper=>1    # means it deletes the directory if empty. 

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head3 import_operator($msg)

This imports a operator message to the filesystem structure

=cut
#------------------------------------------------------------------------------------
# import the new operator status
sub import_operator {
	my $obj=shift; 
	my $msg=shift; 
	$obj->verify_signature($msg);	
	if ( $msg->checksum_period ) { die "I dont know how to deal with ".$msg->type." and checksum_period \n"; }

	my $oldop=$obj->query->operator($msg->call); 
	if ( $oldop ) { 
		if ( $oldop->record_date >= $msg->record_date ) { 
			print STDERR $obj->ts_str." there is an old operator message newer than this one skip this\n"; 
			$msg->link_to_path($obj->{root}."/old");
			return;
		}
		print STDERR $obj->ts_str." I first need to remove the old operator message ".$oldop->checksum."\n"; 
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

	# we need to go through each following $following is holding the followingname
	foreach my $following ($msg->set_of_followings) {
		my $abs_link=$obj->{root}."/followings/".$obj->call2fname($following)."/".$msg->escaped_call;
		print STDERR $obj->ts_str." following operations we need to link $abs_link\n"; 
		if ( ! -e $abs_link ) {
			print STDERR $obj->ts_str." the link does not exist so ensure_path\n"; 
			$obj->ensure_path($obj->{root}."/followings/".$obj->call2fname($following)); 
			print STDERR $obj->ts_str." path ".$obj->{root}."/followings/".$obj->call2fname($following)." ensured\n"; 
			symlink("../../call/".$msg->escaped_call, $abs_link) or die "4 failed to link to following \n"; 
			print STDERR $obj->ts_str." linked "."../../call/".$msg->escaped_call." to ".$abs_link."\n"; 
		}
	}
	
	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call);
	$msg->link_to_path($obj->{root}."/out");
}

#------------------------------------------------------------------------------------
=pod

=head3 remove_operator($msg)

This removes an operator message from the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub remove_operator {
	my $obj=shift; 
	my $msg=shift; 
	
	# remove following entrys
	foreach my $alias ($msg->set_of_aliases) {
		my $f_alias=$obj->call2fname($alias); 
		if ( -l $obj->{root}."/call/$f_alias" ) {
			# yes it is stupid to think that this link points to 
			# our directory TODO: Check that in the future
			unlink($obj->{root}."/call/$f_alias") or die "cant unlink our sylinked $f_alias\n";
		}
	}
	
	# remove alias entrys 
	foreach my $following ($msg->set_of_followings) {
		my $abs_link=$obj->{root}."/followings/".$obj->call2fname($following)."/".$msg->escaped_call;
		if ( -l $abs_link ) {
			# the next foreach removes all messages that where sent via a following to this user
			# this is because the message will not remove itself when the link is gone
			foreach my $file ($obj->scan_dir($abs_link."/telegrams/all", "telegram.+.qtc")) {
				my $telegram=qtc::msg->new(path=>$abs_link."/telegrams/all", filename=>$file); 
				if ( $telegram->to eq $following) { 
					$obj->remove_msg($telegram); 
				}
			}
			unlink($abs_link) or die "cant unlink $abs_link\n"; 
		}
	}
	
	# TODO Operator removal
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call);
	$msg->unlink_at_path($obj->{root}."/out");
}

#------------------------------------------------------------------------------------
=pod

=head3 import_trust($msg)

This imports a telegram message to the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub import_trust {
	my $obj=shift; 
	my $msg=shift; 
	$obj->verify_signature($msg);	
	if ( $msg->checksum_period ) { die "I dont know how to deal with ".$msg->type." and checksum_period \n"; }

	$msg->link_to_path($obj->{root}."/call/".$msg->escaped_call."/trust");

	$msg->link_to_path($obj->{root}."/out");
}

#------------------------------------------------------------------------------------
=pod

=head3 remove_trust($msg)

This removes a trust message from the filesystem structure

=cut
#------------------------------------------------------------------------------------
sub remove_trust {
	my $obj=shift; 
	my $msg=shift; 
	
	$msg->unlink_at_path($obj->{root}."/call/".$msg->escaped_call."/trust");
	$msg->unlink_at_path($obj->{root}."/out");
}

1; 
=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut
