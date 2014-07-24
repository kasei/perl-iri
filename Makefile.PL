use strict;
use warnings;

use inc::Module::Install;

name				'IRI';
all_from			'lib/IRI.pm';
author				'Gregory Todd Williams <gwilliams@cpan.org>';
license				'perl';

build_requires		'Test::More'				=> 0.88;

perl_version		'5.016';

requires			'Moose'						=> 2;

resources(
	'homepage'   => "http://search.cpan.org/dist/IRI/",
	'repository' => "http://github.com/kasei/perl-iri/",
	'bugtracker' => "https://github.com/kasei/perl-iri/issues"
);

author_tests('xt');

sign;

WriteAll;
