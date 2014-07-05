use ExtUtils::MakeMaker;
WriteMakefile(
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
	},
);
