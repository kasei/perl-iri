use strict;
use warnings;

use inc::Module::Install;

name				'IRI';
version				'0.001_01';
all_from			'lib/IRI.pm';
author				'Gregory Todd Williams <gwilliams@cpan.org>';
license				'perl';

build_requires		'Test::More'				=> 0.88;

perl_version		'5.014';

requires			'Moose'						=> 2;
build_requires		'URI'						=> 0;

resources(
	'homepage'   => "http://search.cpan.org/dist/IRI/",
	'repository' => "http://github.com/kasei/perl-iri/",
	'bugtracker' => "https://github.com/kasei/perl-iri/issues"
);

author_tests('xt');

write_doap_changes;
write_doap_changes_xml;

sign;

WriteAll;
