package QSOlog::cli::main; 
use QSOlog::cli; 
@ISA=("QSOlog::cli"); 

sub new {
	my $class=shift; 
	my $obj=$class->SUPER::new(@_); 

	if ( ! defined $obj->{qso} ){ $obj->{qso}={}; }
	return $obj; 
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
	}

}

sub cmd_info {
	my $obj=shift; 

}

sub cmd_qtc {
	my $obj=shift;
	my $which_qtc=shift; 
	
	
}

1; 

