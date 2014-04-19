#!/usr/bin/perl
use qtc::WebApp; 

my $root=$ENV{QTC_ROOT}; 
if ( ! $root ) { $root=$ENV{HOME}."/.qtc" }

my $priv_path_prefix=$ENV{QTC_PRIV_PATH_PREFIX}; 
if ( ! $priv_path_prefix ) { $priv_path_prefix=$ENV{HOME}."/.qtc_web" }

my $app=qtc::WebApp->new(qtc=>{
	path=>$root,
	priv_path_prefix=>$priv_path_prefix,
}); 
$app->run; 
