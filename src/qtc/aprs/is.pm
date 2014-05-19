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

	#if ( ! $obj->{filter} ) { $obj->{filter}="r/48.2090N/16.3700E/500 t/m"; }
	if ( ! $obj->{filter} ) { $obj->{filter}="r/48.2090/16.3700/500 t/m"; }
	#if ( ! $obj->{filter} ) { $obj->{filter}="r/48.2090/16.3700/30000 t/m"; }
	#if ( ! $obj->{filter} ) { $obj->{filter}="t/m"; }



	return $obj; 
}

sub sock { return shift->{sock}; }
sub sel { return shift->{sel}; }
sub query { return shift->{query}; }
sub publish { return shift->{publish}; }

sub eventloop {
	my $obj=shift; 

	while (1) {
		my @ready=$obj->sel->can_read(30);
		# we only have one socket 
		foreach my $sock ( @ready ) {
			# max characters about 120 bytes
			my $buf='';
			if ( ! $sock->connected() ){ 
				 die "Socket $sock not connected connection terminated\n"; 
			}
			if ( ! defined($sock->recv($buf, 120))) { 
				 die "Can't read from $sock\n"; 
			}
			#print STDERR $buf; 
			my $line=$obj->fetch_line($buf); 
			if ( $line ) { $obj->process_line($line); }
			$obj->deliver_telegrams; 
		}
	}
}

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

sub new_filter {
	my $obj=shift; 
	$obj->{filter}=shift;
	$obj->send_filter; 
}

sub send_filter {
	my $obj=shift; 
	
	print STDERR "Sent: "."#filter ".$obj->{filter}."$crlf";
	$obj->sock->send("#filter ".$obj->{filter}."$crlf") or die "Cant send filter\n";
}

sub log_in {
	my $obj=shift; 

	print STDERR "Sent: "."user ".$obj->{user}." pass ".$obj->{pass}." vers QTCNet_to_APRS_IS 0.0.1$crlf";
	$obj->sock->send("user ".$obj->{user}." pass ".$obj->{pass}." vers QTCNet_to_APRS_IS 0.0.1$crlf") or die "Cant send login data\n";
}

sub process_line {
	my $obj=shift; 
	my $line=shift; 

	if ( ! $obj->{login_verified} ) {
		if ( $line =~ /^\# logresp .+ .+, .+ .+$/ ) {
			# logresp logincall verifystatus, server servercall
			print STDERR "RCVD Loginstatus: $line\n"; 
			my ( $hash, $n1, $logresp, $n2,  $logincall, $n3, $verifystatus, $n4,  $server,  $n5, $servercall)=split(/(\s|,)+/, $line); 
			if ( $verifystatus eq "verified" ) { 
				$obj->{login_verified}=1;
				$obj->send_filter; # TODO I will surely forget to adjust this function call here 
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

	if ( $line =~ /^\#.+/ ) {
		print STDERR "RCVD Server Info: $line\n"; 
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
	if ( ( $pkg->type eq ":" ) and ( $pkg->to eq "APQTCCHK" )) {
		print STDERR "APQTCCHK:\n\tfrom: ".$pkg->from."\n\tto: ".$pkg->to."\n\ttext: ".$pkg->msg."\n";
		$obj->process_apqtcchk($pkg);   
	} elsif (( $pkg->type eq ":" ) and ( $pkg->ack )) {
		print STDERR "Message:\n\tfrom: ".$pkg->from."\n\tto: ".$pkg->to."\n\tack: ".$pkg->ack."\n\ttext: ".$pkg->msg."\n";
		print STDERR "I Would send back: ".$pkg->create_ack."\n"; 
		print STDERR "Oh and path is: ".join(",", @{$pkg->path})."\n\n"; 
		$obj->aprs_msg_to_qtc($pkg); 
	} elsif ( $pkg->type eq "ack" ) { 
		print STDERR "Ack:\n\tfrom: ".$pkg->from."\tto: ".$pkg->to."\n\tacked msg: ".$pkg->msg."\n";
		print STDERR "Oh and path is: ".join(",", @{$pkg->path})."\n\n"; 
		$obj->process_ack($pkg); 
	} else {
		#print STDERR "Seen call: ".$pkg->from."\n"; 
		$obj->look_for_telegrams($pkg->from); 
	}
}

sub deliver_telegrams {
	my $obj=shift; 
	my $t=time; 
	foreach my $id (keys %{$obj->{spool}}){
		if ( ($t-$obj->{spool}->{$id}->telegram_date) >= 60 ) {
			print STDERR "publishing ".$obj->{spool}->{$id}->filename."\n"; 
			$obj->publish->publish_telegram($obj->{spool}->{$id});
			print STDERR "Sending ".$obj->{spoolack}->{$id}->create_ack."\n"; 
			$obj->sock->send($obj->{spoolack}->{$id}->create_ack.$crlf);
			delete $obj->{spool}->{$id};
			delete $obj->{spoolack}->{$id};
		}
	}
}

sub process_apqtcchk {
	my $obj=shift;
	my $aprs=shift; 
	my ($id, $chk) = split(" ", $aprs->msg);
	if ( ! $obj->{spool}->{$id} ) { 
		print STDERR "The referenced package $id is never seen by this daemon\n"; 
		return; 
	}
	if ( 
		$obj->chksum_is_lt(
			substr($obj->{spool}->{$id}->checksum, 0, 32),  
			$chk
		)
	) {
		# if our checksum is lower than the received this means we drop our delivery
		# maybe as a feature for later versions we could check if the received telegram 
		# really exists. 
		delete $obj->{spool}->{$id};
		delete $obj->{spoolack}->{$id};
	}	
}

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

sub look_for_telegrams {
	my $obj=shift; 
	my $call=shift; 
	$call=$obj->call_aprs2qtc($call); 
	
	my @telegrams=$obj->query->list_telegrams($call); 
	$obj->{telegrams}->{$call}={};
	foreach my $telegram (@telegrams) {
		print STDERR "Found Telegrams for $call\n"; 
		$obj->deliver_telegram_to_call($call, $telegram); 
	}
}

our $msg_length=67; 
sub deliver_telegram_to_call {
	my $obj=shift; 
	my $call=shift;
	my $telegram=shift;
	
	$obj->{telegrams}->{$call}->{$telegram->checksum}=$telegram;

	my $chk=$telegram->checksum; 
	my $text=$obj->call_qtc2aprs($telegram->to)." // ".$telegram->telegram;

	if ( $call eq $telegram->from ) { 
		print STDERR "Telegram is from the receiver $call itself we are not going to deliver\n"; 
		return; 
	}

	print STDERR "Delivering Telegram ".$telegram->checksum."\n";
	
	my $part=substr($text, 0, 64);
	while ($part) {
		if ( $part =~ /^ack/ ) { $part=".".$part; }
		$text=substr($text, 64);
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
		print STDERR "I am going to sent ".$aprs->generate_msg."\n"; 
		$obj->sock->send($aprs->generate_msg.$crlf); 
		
		# sorry for this complex structure it ist 
		#
		# TO - FROM - CHECKSUM - ACK
		#
		$obj->{sent}->{$aprs->to}->{$aprs->from}->{$telegram->checksum}->{$aprs->ack}=$aprs; 
		
		$part=substr($text, 0, 64);
	}
}

sub process_ack {	
	my $obj=shift; 
	my $aprs=shift;
	
	# 1st delete acked messages from spool 	
	my $id=$aprs->to."_".$aprs->from."_".$aprs->msg; 
	if ( $obj->{spool}->{$id} ) { 
		delete $obj->{spool}->{$id}; 
		delete $obj->{spoolack}->{$id}; 
	}
 	
	# 2nd return if we dont wait for any ack
	if ( ! $obj->{sent}->{$aprs->from}->{$aprs->to} ) { 
		print STDERR "Message ".$aprs->from." ".$aprs->to." is not there\n";
		return; 
	}
	
	# 3rd resolve the acks for aprs messaged we sent 
	foreach my $chk ( keys %{$obj->{sent}->{$aprs->from}->{$aprs->to}} ) {
		delete $obj->{sent}->{$aprs->from}->{$aprs->to}->{$chk}->{$aprs->msg};
		print STDERR "Message deleting ".$aprs->from." ".$aprs->to." ".$aprs->msg." $chk\n";
		my @anz=keys %{$obj->{sent}->{$aprs->from}->{$aprs->to}->{$chk}};
		print STDERR "Anz ".$#anz."\n";
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

sub call_qtc2aprs {
	my $obj=shift; 
	my $call=shift; 
	$call=uc($call); 
	$call=~s/\/\//-/g; 
	return $call; 
}

sub call_aprs2qtc {
	my $obj=shift; 
	my $call=shift; 
	$call=lc($call); 
	$call=~s/-/\/\//g; 
	return $call; 
}

sub aprs_msg_to_qtc {
	my $obj=shift; 
	my $aprs=shift; 
	
	# check if the callsign is active and has an operator
	my $call=$obj->call_aprs2qtc($aprs->to);

	if ( ! $obj->query->operator($call) ) { 
		print STDERR "This operator does not have an operator message, we cant continue\n"; 
		return; 
	}
	
	my $id=$aprs->from."_".$aprs->to."_".$aprs->ack; 

	my $telegram; 

	if ( ! $obj->{spool}->{$id} ) { 
		$telegram=$obj->publish->create_telegram(
			to=>$obj->allowed_letters_for_call($call), 
			from=>$obj->allowed_letters_for_call($obj->call_aprs2qtc($aprs->from)),
			telegram=>$obj->allowed_letters_for_telegram($aprs->msg),
		);
		$obj->{spool}->{$id}=$telegram; 
		$obj->{spoolack}->{$id}=$aprs; 
	} else { 
		$telegram=$obj->{spool}->{$id}; 
		print STDERR "We have already seen message $id, resend just chksum \n";
	}
	
	my $gateinfo=qtc::aprs::packet->new(
		from=>$obj->{user}, 
		to=>"APQTCCHK",
		call=>$obj->{user},
		type=>":",
		msg=>"$id ".substr($telegram->checksum, 0, 32),
	); 
	print STDERR "Sending ".$gateinfo->generate_msg." to APRS IS\n"; 
	$obj->sock->send($gateinfo->generate_msg.$crlf); 
}

1; 
