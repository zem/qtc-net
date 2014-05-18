package qtc::aprs::packet; 

use qtc::misc; 
@ISA=("qtc::misc");
use Data::Dumper; 

sub new {
	my $class=shift; 
	my $obj=$class->SUPER::new(@_); 

	if ( ! $obj->{call} ) { die "I need a call to be able to create a reply path\n"; }
	
	if ( ! $obj->{reply_path} ) { $obj->{reply_path}=[$obj->call, "APQTC1", "WIDE-2"]; }
	if ( ! $obj->{path} ) { $obj->{path}=[$obj->call, "APQTC1", "WIDE2-2"]; }

	if ( $obj->{pkg} ) { $obj->parse_pkg; } 
	
	return $obj; 
}

####################################################
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:OE1SRC-1>APX200,TCPIP*:@172147/4813.50N/01629.80E<000/000/OE1SRC
# 5:NET-> # aprsc 2.0.14-g28c5a6a
# 5:NET-> # logresp OE1SRC-1 verified, server T2BASEL
# 5:NET-> EL-KP4GA>RXTLM-1,TCPIP,qAR,KP4GA::EL-KP4GA:UNIT.RX Erlang,TX Erlang,RXcount/10m,TXcount/10m,none1,STxxxxxx,logic
# 5:NET-> G0DQS-5>APSK20,TCPIP*,qAC,T2TOKYO3::G4FKH    :A,-101.2,-105.8,-107.7,B,-84.1,-92,-100,C,-88.2,-104.6,-106.8,D,-103.9,-110,-111.5,E,-105.8,-111.5,-113
# 5:NET-> 9A7KXP-12>APOT30,WIDE2-1,WIDE2-1,WIDE2-1,IR3DP,WIDE2*,qAR,9A1AAM::9A7KXP-10:PROFILE 1{fi
# 5:NET-> # aprsc 2.0.14-g28c5a6a
# 5:NET-> # logresp OE1SRC-1 verified, server T2GYOR
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)ADL-319!4812.57N/01621.37E$Metalab http://www.metalab.at
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)Monday!5203.56N/00028.92W/Monday Night
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)Sunday!5216.51N/00137.97E/Sunday Night
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)saturday!5155.14N/00036.84E/saturday night
# 5:NET-> OE1SSU-12>APRX28,TCPIP*,qAC,T2ENGLAND:T#176,47.6,0.0,197.0,4.0,0.0,00000000
# 5:NET-> OE3KLU-10>APGE01,TCPIP*,qAC,T2NORWAY:!4808.32N/01628.42E&http://www.aprs.at
# 5:NET-> OE3KLU-10>APGE01,TCPIP*,qAC,T2NORWAY:!4808.32N/01628.42E&QRV DMR TS:WW  
# 5:NET-> OE3BUB-10>APMI04,TCPIP*,qAS,OE3BUB:>Solar Backup aprs + Ghl Profilux3 LiFePO4 13.6V 73 Bernhard
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)Monday!5203.56N/00028.92W/Monday Night
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)Sunday!5216.51N/00137.97E/Sunday Night
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)saturday!5155.14N/00036.84E/saturday night
# 5:TX -> OE1SRC-1>APX200,WIDE2-2::DD5TT    :test{0u}
# 5:TX -> OE1SRC-1>APX200,WIDE2-2::DD5TT    :test{0u}
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)ADL-319!4812.57N/01621.37E$Metalab http://www.metalab.at
# 5:TX -> OE1SRC-1>APX200,WIDE2-2:)Monday!5203.56N/00028.92W/Monday Night
# RCVD Unknown line: PA3FRI>APWW10,TCPIP*,qAC,T2HAM::VK4GO    :ack33
# RCVD Server Info: # aprsc 2.0.14-g28c5a6a 17 May 2014 21:48:11 GMT T2UKRAINE 109.72.122.37:14580
# Found to: DD5TT     to 9
# RCVD Unknown line: OE1SRC-1>APX200,TCPIP*,qAC,T2GYOR::DD5TT    :test .gdhf} test{0v}
# Found to: PA3FRI    to 9
# RCVD Unknown line: VK4GO>APU25N,TCPIP*,qAC,T2SYDNEY::PA3FRI   :zie de webcam maar ff{34
# Found to: VK4GO     to 9
# RCVD Unknown line: PA3FRI>APWW10,TCPIP*,qAC,T2HAM::VK4GO    :ack34
# 

sub parse_pkg {
	my $obj=shift; 
	my $pkg=$obj->{pkg}; 

	$idxfrom=index($pkg, ">");
	$idxpath=index($pkg, ":");
	if ( $idxfrom == -1 ) { die "This package does not seem to have a sender\n"; }
	if ( $idxpath == -1 ) { die "This package does not seem to have a path\n"; }

	my $from=substr($pkg, 0, $idxfrom); 
	#print STDERR "Packet from ".$from."\n"; 
	$obj->{from}=$from;
	my @path=split(",", substr($pkg, $idxfrom+1, $idxpath-$idxfrom-1)); 
	$obj->{path}=\@path;
	#print STDERR "via path ".join("   ", @path)."\n"; 
	my $type=substr($pkg, $idxpath+1, 1);
	$obj->{type}=$type; 
	#print STDERR "has type \"".$type."\"\n"; 
	my $payload=substr($pkg, $idxpath+2);
	$obj->{payload}=$payload; 
	#print STDERR "The payload is ".$payload."\n"; 
	if ( $type eq ":" ) { 
		#print STDERR "we have a message parse payload\n"; 
		$obj->parse_msg_payload; 
	} 
}

sub parse_msg_payload {
	my $obj=shift; 
	my $buf=$obj->{payload}; 
	$idxto=index($buf, ":");
	if ( $idxto == -1 ) { die "That message should have a to call nothing there\n"; }
	
	my $to=substr($buf, 0, $idxto); 
	$to=~s/\s+$//g; 
	$obj->{to}=$to;
	#print STDERR "Found to: $to to $idxto\n"; 

	my $msg=substr($buf, $idxto+1); 

	$obj->{msg}=$msg; 
	
	if (substr($msg, 0, 3) eq 'ack' ) {
		$msg =~ s/^ack\{*//g; 
		$msg =~ s/\}.*$//g; 
		$obj->{type}="ack"; 
		$obj->{msg}=$msg; 
	} else {
		my $idxchk=index($msg, "{");
		if ( $idxchk == -1 ) { 
			# message has no acknowledge 
			return; 
		}
		my $ack=substr($msg, $idxchk+1); 
		$ack =~ s/\}.*$//g; 
		$msg=substr($msg, 0, $idxchk); 
		$obj->{ack}=$ack; 
		$obj->{msg}=$msg; 
	}
}

sub dump {
	my $obj=shift; 
	print STDERR Dumper($obj); 
}

our $AUTOLOAD; 
sub AUTOLOAD {
	my $obj=shift; 
	my $dat=shift; 
	my $method=$AUTOLOAD =~ s/.*:://r; 
	if ( $dat ) { $obj->{$method}=$dat; }
	return $obj->{$method};
}

sub create_ack {
	my $obj=shift; 
	if ( ( $obj->type eq ":" ) and ( $obj->ack ) ) {
		return $obj->to.">".join(",", @{$obj->reply_path})."::".$obj->from.":ack{".$obj->ack."}"; 
	}
}

sub generate_msg {
	my $obj=shift; 
	if ( ( $obj->type eq ":" ) and ( $obj->ack ) ) {
		return $obj->from.">".join(",", @{$obj->path})."::".$obj->to.":".$obj->msg."{".$obj->ack."}"; 
	} elsif ( $obj->type eq ":" ) {
		return $obj->from.">".join(",", @{$obj->path})."::".$obj->to.":".$obj->msg; 
	}
}

1;
