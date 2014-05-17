package qtc::aprs::is; 

use qtc::misc; 
@ISA=("qtc::misc");
use IO::Socket;
use IO::Select;

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

	return $obj; 
}

sub sock { return shift->{sock}; }
sub sel { return shift->{sel}; }

sub fetch_line {
   my $obj=shift; 
   my $sock=shift; 
	# buffer mit recv() oder read lesen.... 
   my $buf=$obj->{'buffer'}; 

   my $index=index($buf, "\n"); 

   if ( $index==-1 ) { return; }

   $obj->{'buffer'}=substr($buf, $index+1); 
   
   my $ret=substr($buf, 0, $index+1);
   chomp($ret); 
   return $ret; 
}

sub set_filter {
	my $obj=shift; 
	my $filterstr=shift; 

}

sub log_in {
	my $obj=shift; 

	$obj->sock->send("user ".$obj->{gatecall}." pass ".$obj->{passcode}." vers QTCNet_to_APRS_IS 0.0.1$crlf") or die "Cant send login data\n";
}

sub process_line {
	my $obj=shift; 
	my $line=shift; 

	if ( ! $obj->{login_verified} ) {
		if ( $line =~ /^\# logresp .+ .+, .+ .+$/ ) {
			# logresp logincall verifystatus, server servercall
			print STDERR "Loginstatus $line"; 
			my ( $hash, $logresp, $logincall, $verifystatus, $server, $servercall)=split(/(\s|,)+/, $line); 
			if ( $verifystatus eq "verified" ) { 
				$obj->{login_verified}=1;
				$obj->set_filter; # TODO I will surely forget to adjust this finction call here 
			} else { 
				die "Login was not verified $line"; 
			}
			return; 
		}
		if ( $line =~ /^\#\s+.+\s+.+$/ ) {
			print STDERR "Server Identification $line"; 
			$obj->log_in; 
			return; 
		}
	}


	print STDERR "Unknown line $line"; 
}


1; 
