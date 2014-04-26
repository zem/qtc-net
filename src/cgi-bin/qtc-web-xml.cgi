#!/usr/bin/perl
use qtc::WebApp::QuickInterface; 

my $root=$ENV{QTC_ROOT}; 
if ( ! $root ) { $root=$ENV{HOME}."/.qtc" }

my $priv_path_prefix=$ENV{QTC_PRIV_PATH_PREFIX}; 
if ( ! $priv_path_prefix ) { $priv_path_prefix=$ENV{HOME}."/.qtc_web" }

my $home_page=$ENV{QTC_HOME_PAGE}; 
if ( ! $home_page ) { $home_page="http://default_to_be_configured/"; }

my $app=qtc::WebApp::QuickInterface->new(qtc=>{
	path=>$root,
	priv_path_prefix=>$priv_path_prefix,
	home_page=>$home_page,
}); 
$app->run; 

