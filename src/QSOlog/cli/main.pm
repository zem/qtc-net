package QSOlog::cli::main; 
use qtc::query; 
use POSIX qw(strftime); 
use QSOlog::cli; 
@ISA=("QSOlog::cli"); 

sub new {
	my $class=shift; 
	my $obj=$class->SUPER::new(@_); 

	if ( ! defined $obj->{qso} ){ $obj->{qso}={}; }
	return $obj; 
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

sub cmd_call {
	my $obj=shift; 
	my $call=shift; 

	if ( ! $call ) { print "usage: call CALLSIGN\n"; return; }

	$call=lc($call); 
	# There should be a working regex to stip any character not allowed from the call 
	# I did not find one... 
	my $t; 
	while ($call) { 
		my $x=substr($call, 0, 1);  $call=substr($call, 1); 
		if ($x=~/([a-z]|[0-9]|\/)/) { $t.=$x; } 
	} 
	$call=$t; 
	
	if ( ! $call ) { 
		print "Having a qso with ".$obj->qso->{call}."\n"
	} else {
		$obj->qso->{call}=$call;
		print "QSO with ".$obj->qso->{call}."\n";
		my $qtc=$obj->qtc_query->num_telegrams($call, "new");
		if ( $qtc ) {
			$obj->cmd_qtc; 
		}
	}

}

sub cmd_info {
	my $obj=shift; 

}

sub cmd_qtc {
	my $obj=shift;
	my $which_qtc=shift; 
	
	@msgs=$obj->qtc_query->list_telegrams($obj->qso->{call}, $which_qtc); 

	print "number of telegrams in QTC Net: ".($#msgs+1)."\n"; 
	print "telegram numbers: "; 
	foreach my $msg (@msgs) { print $msg->hr_refnum." "; }
	print "\n\n";

	foreach my $msg (@msgs) { 
		print "number: ".$msg->hr_refnum."\n"; 
		print "from: ".$msg->from."\t"; 
		print "to: ".$msg->to."\t"; 
		print "date: ".strftime("%Y-%m-%d %H:%M:%S UTC", gmtime($msg->telegram_date))."\n"; 
		print "text: ".$msg->telegram."\n"; 
		print "\n"; 
	}
}

1; 

