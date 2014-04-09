package qtc::misc; 
use File::Basename; 

sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	return $obj; 
}

# an escaped call for filesystem purposes
sub fname2call {
	my $obj=shift; 
	my $call=shift; 
	if ( ! $call ) { die "we should get a callsign as parameter to this function\n"; } 
	$call=~s/-/\//g; 
	return $call; 
}

# an escaped call for filesystem purposes
sub call2fname {
	my $obj=shift; 
	my $call=shift; 
	if ( ! $call ) { die "we should get a callsign as parameter to this function\n"; } 
	$call=~s/\//-/g; 
	return $call; 
}

############################################################
# maybe we can borrow this from some sort of helper lib
############################################################
sub ensure_path {
	my $obj=shift; 
	my $path=shift;
	if (( -e $path ) and ( ! -d $path ) and ( ! -l $path ))  {
		die "there is something at this path $path neither directory nor link\n"; 
	}
	if (! -e $path )  {
		# create directory here 
		$obj->ensure_path(dirname($path)); 
		mkdir($path) or die "Can't mkdir $path\n"; 
	}
	# it is ok otherwise
}

sub scan_dir {
	my $objSelf=shift;
	my $sDir=shift;
	my $sPrefix=shift; 
	my @aFiles=shift; 

	if ( ! $sDir ) { die "I need a directory to scan\n"; }
	if ( ! $sPrefix ) { die "I need an expression to scan for\n"; }

	if ( ! -e $sDir ) { 
			# the directory does not exist this (and only this) means return
			return(); 
	}

	opendir(DIR, $sDir) or die "directory $sDir to scan is not there\n";

	eval "\@aFiles = grep { /$sPrefix/ } readdir DIR";
		
	closedir DIR;
	
	@aFiles = grep { ! /^(\.|\.\.)$/ } @aFiles;	# filter . and ..

	return (@aFiles);
}

1; 
