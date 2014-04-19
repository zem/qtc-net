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

sub get_pid {
	my $o=shift; 
	my $pfile=$o->{pidfile}; 

	if ( ! -f $pfile ) { return undef; }
	
	my $p; 
	open(PID, "< $pfile") or die "cant open pidfile\n"; 
	while(<PID>) { $p.=$_; }
	close PID ; 
	
	return $p; 
}

sub wakeup_processor {
	my $obj=shift;
	eval { 
		if ( -e $obj->{pidfile} ) {
			kill('HUP', $obj->get_pid); 
		}
	};
}


###############################################
# the allowed letters routinges will strip 
# down user data as needed. 
###############################################
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

1; 
