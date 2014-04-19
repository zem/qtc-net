#!/usr/bin/perl
use qtc::WebApp; 
my $app=qtc::WebApp->new(qtc=>{
	path=>"/home/zem/.qtc",
	priv_path_prefix=>"/tmp/qtc_web",
}); 
$app->run; 
