package qtc::aprs::is; 

use qtc::misc; 
@ISA=("qtc::misc");
use IO::Socket;
use IO::Select;
use qtc::aprs::packet; 
use qtc::query; 
use qtc::publish; 

# we use this object global variable to be sure to use crlf on all plattforms
our $crlf=pack("H*", "0D0A"); 

# setup object
sub new {
	my $class=shift; 
	my $obj=$class->SUPER::new(@_); 

	$obj->{publish}=qtc::publish->new(
   	path=>$obj->{path},
   	privpath=>$obj->{privpath},
	); 
	
	$obj->{query}=qtc::query->new(
   	path=>$obj->{path},
	); 

	if ( ! $obj->{user} ) { $obj->{user}=$obj->call_qtc2aprs($obj->publish->{call}); }

	$obj->{sock} = IO::Socket::INET->new(
		PeerAddr=>$obj->{PeerAddr},
		Proto    => 'tcp',
	);	
	
	$obj->{sel} = IO::Select->new($obj->sock);	

	$obj->{server_info_timeout}=1800; 

	#if ( ! $obj->{filter} ) { $obj->{filter}="r/48.2090N/16.3700E/500 t/m"; }
	if ( ! $obj->{filter} ) { $obj->{filter}="r/48.2090/16.3700/500 t/sm"; }
	#if ( ! $obj->{filter} ) { $obj->{filter}="r/48.2090/16.3700/30000 t/m"; }
	#if ( ! $obj->{filter} ) { $obj->{filter}="t/m"; }



	return $obj; 
}

sub sock { return shift->{sock}; }
sub sel { return shift->{sel}; }
sub query { return shift->{query}; }
sub publish { return shift->{publish}; }

# the main eventloop for the daemon 
sub eventloop {
	my $obj=shift; 
	
	$obj->{last_server_info}=time; 

	while (1) {
		my @ready=$obj->sel->can_read(30);
		# we only have one socket 
		foreach my $sock ( @ready ) {
			# max characters about 120 bytes
			my $buf='';
			if ( ! $sock->connected() ){ 
				 die "Socket $sock not connected connection terminated\n"; 
			}
			if ( $obj->{server_info_timeout} ) {
				if ( $obj->{last_server_info} < time-$obj->{server_info_timeout} ) {
					die "Server info timeout! ".($obj->{last_server_info})." we will close the connection here\n"; 
				}
			}
			if ( ! defined($sock->recv($buf, 120))) { 
				 die "Can't read from $sock\n"; 
			}
			#print STDERR $buf; 
			my $line=$obj->fetch_line($buf); 
			if ( $line ) { $obj->process_line($line); }
			$obj->deliver_telegrams; 
			foreach my $id (keys %{$obj->{acked_msgs}}) {
				if ( $obj->{acked_msgs}->{$id} < time-100000 ) { # abt 1 day 
					delete $obj->{acked_msgs}->{$id};
				}
			}
		}
	}
}

# read exactly one line from a socket if there 
sub fetch_line {
   my $obj=shift; 
   my $buf=shift; 
	# buffer wurre vorher mit recv oder read gelesen  
   $obj->{buffer}.=$buf; 
   $buf=$obj->{buffer}; 

   my $index=index($buf, $crlf); 

   if ( $index==-1 ) { return; }

   $obj->{'buffer'}=substr($buf, $index+2); 
   
   my $ret=substr($buf, 0, $index);
   return $ret; 
}

# set a new filter 
sub new_filter {
	my $obj=shift; 
	$obj->{filter}=shift;
	$obj->send_filter; 
}

# send a filter to the remote IS gateway 
sub send_filter {
	my $obj=shift; 
	
	print STDERR "Sent: "."#filter ".$obj->{filter}."$crlf";
	$obj->sock->send("#filter ".$obj->{filter}."$crlf") or die "Cant send filter\n";
}

# log into the aprs is server 
sub log_in {
	my $obj=shift; 

	print STDERR "Sent: "."user ".$obj->{user}." pass ".$obj->{pass}." vers QTCNet_to_APRS_IS 0.0.1$crlf";
	$obj->sock->send("user ".$obj->{user}." pass ".$obj->{pass}." vers QTCNet_to_APRS_IS 0.0.1$crlf") or die "Cant send login data\n";
}

# process a line fetched from the server
sub process_line {
	my $obj=shift; 
	my $line=shift; 

	if ( $obj->{debug} ) {
		print STDERR $line."\n"; 
	}
	if ( ! $obj->{login_verified} ) {
		if ( $line =~ /^\# logresp .+ .+, .+ .+$/ ) {
			# logresp logincall verifystatus, server servercall
			print STDERR "RCVD Loginstatus: $line\n"; 
			my ( $hash, $n1, $logresp, $n2,  $logincall, $n3, $verifystatus, $n4,  $server,  $n5, $servercall)=split(/(\s|,)+/, $line); 
			if ( $verifystatus eq "verified" ) { 
				$obj->{login_verified}=1;
				$obj->send_filter; # TODO I will surely forget to adjust this function call here 
				$obj->{last_filter}=time; 
			} else { 
				die "Login was not verified $verifystatus -- $hash - $logresp - $logincall - $verifystatus\n"; 
			}
			return; 
		}
		if ( $line =~ /^\#\s+.+\s+.+$/ ) {
			print STDERR "RCVD Server Identification: $line\n"; 
			$obj->log_in; 
			return; 
		}
	}

	if ( $obj->{last_filter}+3600 <= time ) {
		$obj->send_filter; # TODO I will surely forget to adjust this function call here 
		$obj->{last_filter}=time; 
	}

	if ( $line =~ /^\#.+/ ) {
		print STDERR "RCVD Server Info: $line\n"; 
		$obj->{last_server_info}=time; 
		return; 
	}

	my $pkg; 
	eval {
		$pkg=qtc::aprs::packet->new(pkg=>$line, call=>$obj->{user}); 	
		#$pkg->dump; 
	};
	if ( $@ ) {
		print STDERR "Parsing failed: $@\n"; 
		print STDERR "RCVD Unknown line: $line\n"; 
		return; 
	}
	if (( $pkg->type eq ":" ) and ( $pkg->ack ) and ( ! $pkg->path_hash->{APQTC1} ) ) {
		print STDERR "Message:\n\tfrom: ".$pkg->from."\n\tto: ".$pkg->to."\n\tack: ".$pkg->ack."\n\ttext: ".$pkg->msg."\n";
		#print STDERR "I Would send back: ".$pkg->create_ack."\n"; 
		#print STDERR "Oh and path is: ".join(",", @{$pkg->path})."\n\n"; 
		$obj->aprs_msg_to_qtc($pkg); 
		$obj->look_for_telegrams($pkg->from); 
	} elsif ( $pkg->type eq "ack" ) { 
		print STDERR "Ack:\n\tfrom: ".$pkg->from."\tto: ".$pkg->to."\n\tacked msg: ".$pkg->msg."\n";
		print STDERR "Oh and path is: ".join(",", @{$pkg->path})."\n\n"; 
		$obj->process_ack($pkg); 
		if ( ! $pkg->path_hash->{APQTC1} ) { 
			$obj->look_for_telegrams($pkg->from);
		}
	} else {
		#print STDERR "Seen call: ".$pkg->from."\n"; 
		if ( $obj->look_for_telegrams($pkg->from) ) {
			print STDERR "message was: $line \n"; 
		} 
	}
}

# publishes a telegram in qtc and sends the Acknowledge back to aprs 
sub deliver_telegrams {
	my $obj=shift; 
	my $t=time; 
	foreach my $id (keys %{$obj->{spool}}){
		if ( ($t-$obj->{spool}->{$id}->telegram_date) >= $obj->{spooltimeout}->{$id} ) {
			print STDERR "publishing ".$obj->{spool}->{$id}->filename."\n"; 
			my $telegram=$obj->{spool}->{$id};
			if (
				( $obj->query->telegram_by_checksum($telegram->checksum) ) 
				or ( $obj->query->telegram_by_checksum($telegram->prev_checksum) ) 
				or ( $obj->query->telegram_by_checksum($telegram->next_checksum) )
				or ( $obj->query->msg_already_exists($telegram) )
			) {
				# I will not publish just ack, telegram is already there in the net
				print STDERR "Not publishing telegram ".$telegram->filename.", checksum already there\n"; 
			} else {
				print STDERR "Publishing telegram ".$telegram->filename."\n"; 
				$obj->publish->publish_telegram($obj->{spool}->{$id});
			}
			print STDERR "Sending ".$obj->{spoolack}->{$id}->create_ack."\n"; 
			$obj->sock->send($obj->{spoolack}->{$id}->create_ack.$crlf);
			$obj->{acked_msgs}->{$id}=time; 
			delete $obj->{spool}->{$id};
			delete $obj->{spoolack}->{$id};
			delete $obj->{spooltimeout}->{$id};
			delete $obj->{spool_others}->{$id};
		}
	}
}

# looks if there are new telegrams available for $call
sub look_for_telegrams {
	my $obj=shift; 
	my $call=shift; 
	$call=$obj->call_aprs2qtc($call); 
	
	my $ret=0; 
	
	my @telegrams=$obj->query->list_telegrams($call); 
	$obj->{telegrams}->{$call}={};
	foreach my $telegram (@telegrams) {
		print STDERR "Found Telegrams for $call\n"; 
		$obj->deliver_telegram_to_call($call, $telegram); 
		$ret=1;
	}
	return $ret; 
}

# deliver a specific telegram to a call if seen 
our $msg_length=67-4; 
sub deliver_telegram_to_call {
	my $obj=shift; 
	my $call=shift;
	my $telegram=shift;
	
	$obj->{telegrams}->{$call}->{$telegram->checksum}=$telegram;

	my $chk=$telegram->checksum; 
	#my $text=$obj->call_qtc2aprs($telegram->to)." // ".$telegram->telegram;
	my $text=$telegram->telegram;

	if ( $call eq $telegram->from ) { 
		print STDERR "Telegram is from the receiver $call itself we are not going to deliver\n"; 
		return; 
	}
	

	my @anz=keys %{$obj->{sent}->{$obj->call_qtc2aprs($call)}->{$obj->call_qtc2aprs($telegram->from)}->{$chk}};
	print STDERR "Delivering Telegram ".$chk." ".$obj->call_qtc2aprs($telegram->from)." ".$obj->call_qtc2aprs($call)." anz is ".($#anz)."\n";

	print STDERR "Delivering Telegram ".$telegram->checksum." anz is ".($#anz)."\n";
	
	my $part=substr($text, 0, $msg_length);
	while ($part) {
		if ( $part =~ /^ack/ ) { $part=".".$part; }
		$text=substr($text,  $msg_length);
		my $ack=$telegram->hr_refnum($chk); 
		$chk=substr($chk, 8);
		my $aprs=qtc::aprs::packet->new(
			from=>$obj->call_qtc2aprs($telegram->from),
			to=>$obj->call_qtc2aprs($call),
			call=>$obj->{user},
			type=>":",
			msg=>$part,
			ack=>$ack,
		);
		if (
			( $#anz < 0 )
			or ( $obj->{sent}->{$aprs->to}->{$aprs->from}->{$telegram->checksum}->{$aprs->ack} ) 
		) { 
			print STDERR "I am going to sent this part of the telegram ".$aprs->generate_msg."\n"; 
			$obj->sock->send($aprs->generate_msg.$crlf); 
			# sorry for this complex structure it ist 
			#
			# TO - FROM - CHECKSUM - ACK
			#
			$obj->{sent}->{$aprs->to}->{$aprs->from}->{$telegram->checksum}->{$aprs->ack}=$aprs; 
		} else {
			print STDERR "This part of the Telegram is already acked ".$aprs->generate_msg."\n"; 
		} 
		
		$part=substr($text, 0, $msg_length);
	}
}

# we got an ack lets see what we have to do with it 
sub process_ack {	
	my $obj=shift; 
	my $aprs=shift;
	
	# 1st delete acked messages from spool 	
	# hope that we will never see another one agn. 
	my $id=$aprs->to."_".$aprs->from."_".$aprs->msg; 
	if ( $obj->{spool}->{$id} ) { 
		delete $obj->{spool}->{$id}; 
		delete $obj->{spoolack}->{$id}; 
		delete $obj->{spooltimeout}->{$id};
		$obj->{acked_msgs}->{$id}=time; 
	}
 	
	# 2nd return if we dont wait for any ack
	if ( ! $obj->{sent}->{$aprs->from}->{$aprs->to} ) { 
		print STDERR "Message ".$aprs->from." ".$aprs->to." is not there\n";
		return; 
	}
	
	# 3rd resolve the acks for aprs messages that we sent to a station 
	foreach my $chk ( keys %{$obj->{sent}->{$aprs->from}->{$aprs->to}} ) {
		delete $obj->{sent}->{$aprs->from}->{$aprs->to}->{$chk}->{$aprs->msg};
		print STDERR "Message deleting ".$aprs->from." ".$aprs->to." $chk ".$aprs->msg."\n";
		my @anz=keys %{$obj->{sent}->{$aprs->from}->{$aprs->to}->{$chk}};
		print STDERR "Anz keys for $chk is".$#anz."\n";
		if ( $#anz == -1  ) { 
			print STDERR "oh the package $chk is done send qsp\n"; 
			#sleep 1; 
			$obj->publish->qsp(
				to=>$obj->call_aprs2qtc($aprs->from), 
				msg=>$obj->{telegrams}->{$obj->call_aprs2qtc($aprs->from)}->{$chk} 
			); 
			print STDERR "telegram  ".$obj->{telegrams}->{$obj->call_aprs2qtc($aprs->from)}->{$chk}->checksum." qsped \n"; 
			# we need to delete the chksum as well to prevent doubled telegrams 
			delete $obj->{sent}->{$aprs->from}->{$aprs->to}->{$chk}; 
		}
	}
}

# callsign transformation 
sub call_qtc2aprs {
	my $obj=shift; 
	my $call=shift; 
	$call=uc($call); 
	$call=~s/\/\//-/g; 
	return $call; 
}

# callsign transformation 
sub call_aprs2qtc {
	my $obj=shift; 
	my $call=shift; 
	$call=lc($call); 
	$call=~s/-/\/\//g; 
	return $call; 
}

# try to deliver this aprs message to QTC network 
sub aprs_msg_to_qtc {
	my $obj=shift; 
	my $aprs=shift; 
	
	# check if the callsign is active and has an operator
	my $call=$obj->call_aprs2qtc($aprs->to);
	my $from=$obj->call_aprs2qtc($aprs->from);

	if ( ! $obj->query->operator($from) ) { 
		print STDERR "This operator does not have an operator message, we try target\n"; 
		if ( ! $obj->query->operator($call) ) { 
			print STDERR "neither sender nor receiver have an operator message we will stop processing of this msg here\n"; 
			return;
		} 
	}
	
	my $id=$aprs->from."_".$aprs->to."_".$aprs->ack; 

	if ( $obj->{acked_msgs}->{$id} ) {
		# we already published that telegram in qtc send back ack and forget about it 
		print STDERR "Message already acked Resending ".$aprs->create_ack."\n"; 
		$obj->sock->send($aprs->create_ack.$crlf);
		return; 
	}

	my $telegram; 

	if ( ! $obj->{spool}->{$id} ) { 
		$telegram=$obj->publish->create_telegram(
			to=>$obj->allowed_letters_for_call($call), 
			from=>$obj->allowed_letters_for_call($obj->call_aprs2qtc($aprs->from)),
			telegram=>$obj->allowed_letters_for_telegram($aprs->msg),
			checksum_period=>100000, # abt 1 day 
		);
		if (
			( $obj->query->telegram_by_checksum($telegram->checksum) ) 
			or ( $obj->query->telegram_by_checksum($telegram->prev_checksum) ) 
			or ( $obj->query->telegram_by_checksum($telegram->next_checksum) )
			or ( $obj->query->msg_already_exists($telegram) )
		) {
			# telegram already is in QTC net 
			$obj->sock->send($aprs->create_ack.$crlf);
			$obj->{acked_msgs}->{$id}=time; 
			return; 
		}
		$obj->{spool}->{$id}=$telegram; 
		$obj->{spoolack}->{$id}=$aprs; 
		$obj->{spooltimeout}->{$id}=60; 
	} else { 
		$telegram=$obj->{spool}->{$id}; 
		print STDERR "We have already seen message $id, resend just chksum \n";
	}
}

1; 
