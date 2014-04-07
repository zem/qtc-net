package QSOlog::cli::main; 
use qtc::query; 
use qtc::publish; 
use POSIX qw(strftime); 
use QSOlog::cli; 
@ISA=("QSOlog::cli"); 

sub new {
	my $class=shift; 
	my $obj=$class->SUPER::new(@_); 
	
	if ( ! defined $obj->{qso} ){ $obj->{qso}={}; }
	#if ( ! $obj->{mycall} ) { $obj->cmd_mycall;  } # TODO make this configurable

	return $obj; 
}

# returns a query object for the QTC network 
sub qtc_publish { 
	if ( ! $obj->{qtc_publish} ) { 
		$obj->{qtc_publish}=qtc::publish->new(); 
	}
	return $obj->{qtc_publish}; 
}

# returns a query object for the QTC network 
sub qtc_query { 
	if ( ! $obj->{qtc_query} ) { 
		$obj->{qtc_query}=qtc::query->new(); 
	}
	return $obj->{qtc_query}; 
}

sub config_cmds {
	my $obj=shift; 
	$obj->SUPER::config_cmds; 
	$obj->{cmds}->{call}="set the call of your qso partner"; 
	$obj->{cmds}->{qtc}="shows messages for this call"; 
	$obj->{cmds}->{qsp}="confirm that qtc messages are transferred to a call"; 
	$obj->{cmds}->{info}="show infos about the ongoing QSO"; 
	$obj->{cmds}->{mycall}="set your own call"; 
	$obj->{cmds}->{setup}="start setup mode"; 
	$obj->{cmds}->{telegram}="send a telegram"; 
	$obj->{cmds}->{save}="save QSO record"; 
	$obj->{cmds}->{cancel}="cancel QSO record"; 
	$obj->{cmds}->{qrg}="insert qrg for the qso"; 
	$obj->{cmds}->{date}="configure date of the qso"; 
	$obj->{cmds}->{time}="configure time of the qso"; 
	$obj->{cmds}->{trust}="sends QTC trustmessage for this call"; 
	$obj->{cmds}->{qth}="sets qth for this call"; 
	$obj->{cmds}->{qra}="sets maidenhead locator of this call"; 
	$obj->{cmds}->{name}="sets name of the qso partner"; 
	$obj->{cmds}->{mode}="set the mode you are operating in"; 
	$obj->{cmds}->{notes}="additional notes for this QSO"; 
}

# returns the data hash 
sub qso {
	my $obj=shift; 
	return $obj->{qso}; 
}

sub allowed_letters_for_telegram {
	my $obj=shift; 
	my $telegram=shift; 
	
	$telegram=lc($telegram); 
	$telegram=~s/\t/\ /g; 
	# There should be a working regex to stip any character not allowed from the call 
	# I did not find one... 
	my $t;
	while ($telegram) { 
		my $x=substr($telegram, 0, 1);  $telegram=substr($telegram, 1); 
		if ($x=~/([a-z]|[0-9]|\/|\.|,|\ |\?)/) { $t.=$x; } 
		if ( length($t) >= 300 ) { $telegram=''; }
	} 
	return $t; 
}

sub allowed_letters_for_call {
	my $obj=shift; 
	my $call=shift; 
	
	$call=lc($call); 
	# There should be a working regex to stip any character not allowed from the call 
	# I did not find one... 
	my $t; 
	while ($call) { 
		my $x=substr($call, 0, 1);  $call=substr($call, 1); 
		if ($x=~/([a-z]|[0-9]|\/)/) { $t.=$x; } 
	} 
	return $t; 
}

sub cmd_call {
	my $obj=shift; 
	my $call=shift; 

	if ( ! $call ) { print "usage: call CALLSIGN\n"; return; }

	$call=$obj->allowed_letters_for_call($call); 
	
	if ( ! $call ) { 
		print "Having a qso with ".$obj->qso->{call}."\n"
	} else {
		$obj->qso->{call}=$call;
		$obj->qso->{current_telegrams}={}; 
		print "QSO with ".$obj->qso->{call}."\n";
		my $qtc=$obj->qtc_query->num_telegrams($call, "new");
		if ( $qtc ) {
			$obj->cmd_qtc; 
		}
	}
}

sub cmd_telegram {
	my $obj=shift; 
	my $to=shift;
	my $telegram=shift; 

#	if ( ! $obj->{mycall} ) { 
#		print "You did not configure your call, so I do not know who published the telegram.\n
#Please start qso by using mycall CALLSIGN\n";
#		return; 
#	}
	if ( ! $obj->qso->{call} ) { 
		print "There is no call set for this QSO, so I do not know who send the telegram.\n
Please start qso by using call CALLSIGN\n";
		return; 
	}
	
	if ( ! $to ) {
		$to=$obj->ask_something("telegram to"); 
		if ( ! $to) { print "Abort empty receiver\n"; return; }
	}
	$to=$obj->allowed_letters_for_call($to); 

	if ( ! $telegram ) {
		$telegram=$obj->ask_something("telegram text"); 
		if ( ! $telegram ) { print "Abort empty message\n"; return; }
	}
	$telegram=$obj->allowed_letters_for_telegram($telegram); 
	
	print "should I send the following telegram:\n"; 
	print "\tfrom: ".$obj->qso->{call}."\n"; 
	print "\tto: ".$to."\n"; 
	print "\ttelegram: ".$telegram."\n";

	my $yes=$obj->ask_something("yes/no", "yes"); 
	if ( $yes ne "yes" ) { 
		print "Answer is $yes, aborting \n"; return; 
	}
	$obj->qtc_publish->telegram(
		from=>$obj->qso->{call},
		to=>$to, 
		telegram=>$telegram, 
	);
}

sub cmd_info {
	my $obj=shift; 

	print "INFO about the qso to be implemented\n"; 
}

sub cmd_qtc {
	my $obj=shift;
	my $which_qtc=shift; 
	
	@msgs=$obj->qtc_query->list_telegrams($obj->qso->{call}, $which_qtc); 

	print "number of telegrams in QTC Net: ".($#msgs+1)."\n"; 
	print "telegram numbers: "; 
	foreach my $msg (@msgs) { 
		print $msg->hr_refnum." ";
		# store msgs by their refnum into the qso hash
		$obj->qso->{current_telegrams}->{$msg->hr_refnum}->{$msg->checksum}=$msg; 
	}
	print "\n\n";

	foreach my $msg (@msgs) { 
		$obj->print_msg($msg); 
	}
}

sub print_msg {
	my $obj=shift; 
	my $msg=shift; 
	print "number: ".$msg->hr_refnum."\n"; 
	print "from: ".$msg->from."\t"; 
	print "to: ".$msg->to."\t"; 
	print "date: ".strftime("%Y-%m-%d %H:%M:%S UTC", gmtime($msg->telegram_date))."\n"; 
	print "telegram: ".$msg->telegram."\n"; 
	print "\n"; 
}

sub cmd_mycall {
	my $obj=shift; 
	my $mycall=shift; 
	
	if ( ! $mycall ) {
		$mycall=$obj->ask_something("YOUR call", "oe1src"); 
		if ( ! $mycall) { print "Your call is should not be empty use mycall CALLSIGN to set one\n"; }
	}
	$mycall=$obj->allowed_letters_for_call($mycall);

	print "Hello $mycall\n"; 
	$obj->{mycall}=$mycall; 
	
}

sub cmd_qsp {
	my $obj=shift; 
	my @refnums=@_; 

	if ( ! $obj->qso->{call} ) { 
		print "There is no call set for this QSO, so I do not know who send the telegram.\n
Please start qso by using call CALLSIGN\n";
		return; 
	}
	
	if ($#refnums < 0 ) {
		print "please type in the numbers of the telegrams you transferred to ".$obj->qso->{call}." separated by space\n"; 
		@refnums=$obj->split_line($obj->ask_something("transmitted telegram numbers"));
	}
	
	print ("Should I Sent qsp for the following Telegrams?\n");
	print join(" ", @refnums); 
	my $yes=$obj->ask_something("yes/no", "yes"); 
	if ( $yes ne "yes" ) { 
		print "Answer is $yes, aborting \n"; return; 
	}

	foreach my $refnum (@refnums) {
		if ( ! defined $obj->qso->{current_telegrams}->{$refnum} ) {
			print "The Telegram $refnum is unknown. This usually means you did not see it with qsp or call cmd\n"; 
			next; 
		}
		my @msg_checksums=keys $obj->qso->{current_telegrams}->{$refnum};
		if ( $#msg_checksums > 0 ) {
			my @t; 
			print "The Telegram $refnum is not precise. This usually means there is the same refnum twice."
			print "So I have to ask you.\n";
			foreach my $msg_checksum (@msg_checksums) {
				$obj->print_msg($obj->qso->{current_telegrams}->{$refnum}->{$msg_checksum}); 
				print "This one?"
				my $yes=$obj->ask_something("yes/no", "yes"); 
				if ( $yes ne "yes" ) { 
					print "Answer is $yes, not qspint \n"; next;
				}
				push @t, $msg_checksum; 
			} 
			@msg_checksums=@t; 
		} 
		foreach my $msg_checksum (@msg_checksums) {
			$obj->qtc_publish->telegram(
				to=>$obj->qso->{call},
				msg=>$obj->qso->{current_telegrams}->{$refnum}->{$msg_checksum}, 
			);
		}	
	}
}


1; 

