package qtc::aprs::is; 

use qtc::misc; 
@ISA=("qtc::misc");
use IO::Socket;
use IO::Select;
use qtc::aprs::packet; 

# we use this object global variable to be sure to use crlf on all plattforms
our $crlf=pack("H*", "0D0A"); 

sub new {
	my $class=shift; 
	my $obj=$class->SUPER::new(@_); 

	$obj->{sock} = IO::Socket::INET->new(
		PeerAddr=>$obj->{PeerAddr},
		Proto    => 'tcp',
	);	
	
	$obj->{sel} = IO::Select->new($obj->sock);	

	#if ( ! $obj->{filter} ) { $obj->{filter}="r/4820.90N/1637.00E/1000 t/m"; }
	if ( ! $obj->{filter} ) { $obj->{filter}="t/m"; }

	return $obj; 
}

sub sock { return shift->{sock}; }
sub sel { return shift->{sel}; }

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

	eval {
		my $pkg=qtc::aprs::packet->new(pkg=>$line); 	
		$pkg->dump; 
	};
	if ( $@ ) {
		print STDERR "Parsing failed: $@\n"; 
		print STDERR "RCVD Unknown line: $line\n"; 
	}
}



1; 
