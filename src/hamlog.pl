#!/usr/bin/perl
use hamlog::cli; 

my $cli=hamlog::cli->new(); 

$cli->loop; 

#print join("--", $cli->split_line(" ABC \"DEF\" GH\\ I JKL"))."\n"; 

