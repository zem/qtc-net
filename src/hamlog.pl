#!/usr/bin/perl
use hamlog::cli::main; 

print <<EOS

Welcome to QSO Log Application when it is grown up it will be a ham 
radio log program. For now it is a Testing command line Application 
for QTC Net Messages.

Try help to get help or start a qso by setting a call with call [call]

EOS
;

my $cli=hamlog::cli::main->new(); 

$cli->loop; 

#print join("--", $cli->split_line(" ABC \"DEF\" GH\\ I JKL"))."\n"; 

