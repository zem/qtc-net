package qtc::query; 
use File::Basename; 
use qtc::msg; 
use qtc::misc; 
@ISA=("qtc::misc"); 


# this package provides methods that deliver 
# specific messages.....

sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ( ! $obj->{path} ) { $obj->{path}=$ENV{HOME}."/.qtc"; }
	return $obj; 
}

sub list_telegrams { 
	my $obj=shift; 
	my $call=shift; 
	my $type=shift; 
	
	$misc->ensure_path($ENV{HOME}."/.qtc/call/$call/telegrams/$type");
	my @msgs;
	foreach my $file ($misc->scan_dir($ENV{HOME}."/.qtc/call/$call/telegrams/new", '.+\.qtc')){
		push @msgs, qtc::msg->new(path=>$ENV{HOME}."/.qtc/call/$call/telegrams/new", filename=>$file); 
	}
	return @msgs; 
}

1; 
