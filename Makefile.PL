use ExtUtils::MakeMaker;
WriteMakefile(
	FIRST_MAKEFILE=>'Makefile.PL.mk',
	NAME         => 'qtc::net',
	VERSION => '0.0.1', 
	'PREREQ_PM' => {
		'POSIX' => '0',
		'Crypt::OpenSSL::RSA' => '0',
		'Crypt::OpenSSL::DSA' => '0',
		'Digest::SHA' => '0',
		'MIME::Base64' => 0,
		'LWP::UserAgent' => 0,
		'CGI::Application' => 0,
		'CGI' => 0,
		'Data::Dumper' => 0,
		'Archive::Tar' => 0,
		'IO::Scalar'=>0,
		'Authen::Captcha'=>0, 
		'File::Copy'=>0, 
		'File::ExtAttr'=>0, 
	},
	AUTHOR=>[
		"Hans Freitag <oe1src\@oevsv.at>",
	],
	ABSTRACT=>"QTC Net is a short Telegram System for Amateur Radio.",
	EXE_FILES=>[qw(
		bin/qtc_aprs.pl
		bin/qtc_aprs_pkg.pl
		bin/qtc_dump_msg.pl
		bin/qtc_keygen.pl
		bin/qtc_process_in.pl
		bin/qtc_process_in_loop.pl
		bin/qtc_publish_http.pl
		bin/qtc_sync_http.pl
	)],
);
