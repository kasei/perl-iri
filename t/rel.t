#!/usr/bin/perl

use v5.14;
use strict;
use warnings;
no warnings 'redefine';
use Test::More;
use Data::Dumper;
use Encode qw(decode_utf8);
use URI;
use utf8;

binmode(\*STDOUT, ':utf8');

use IRI;

sub confirm_tests {
	my $base	= URI->new(shift->abs);
	my $b		= $base->as_string;
	my $tests	= shift;
	my @tests	= @$tests;
	while (my ($url, $expect) = splice(@tests, 0, 2, ())) {
		my $i	= URI->new($url);
		my $r	= $i->rel($base);
		my $u	= URI->new_abs($expect, $base)->as_string;
		is($u, $url, "CONFIRM: $url [$b]");
	}
}

sub run_tests {
	my $base	= shift;
	my $b		= $base->abs;
	my $tests	= shift;
	my @tests	= @$tests;
	while (my ($url, $expect) = splice(@tests, 0, 2, ())) {
		my $i	= IRI->new(value => $url);
		my $r	= $i->rel($base);
# 		warn "Turning " . $i->abs . " into a relative IRI using base $b ===> " . $r->abs;
		is($r->as_string, $expect, "$url [$b]");
	}
}

subtest 'rel: scheme,host' => sub {
	my $base	= IRI->new(value => "http://www.example.org/");
	my @REL_TESTS	= (
		'http://www.example.com/'			=> '//www.example.com/',
		'https://www.example.org/'			=> 'https://www.example.org/',
		'http://www.example.org/'			=> '',
		'http://www.example.org/foo'		=> 'foo',
		'http://www.example.org/foo/bar'	=> 'foo/bar',
		'http://www.example.org/#hello'		=> '#hello',
		'http://www.example.org/?query'		=> '?query',
		'http://www.example.org/foo?query'		=> 'foo?query',
	);
	run_tests($base, \@REL_TESTS);
	confirm_tests($base, \@REL_TESTS);
};

subtest 'rel: scheme,host,path' => sub {
	my $base	= IRI->new(value => "http://www.example.org/foo/bar");
	my @REL_TESTS	= (
		'http://www.example.com/'			=> '//www.example.com/',
		'https://www.example.org/'			=> 'https://www.example.org/',
		'http://www.example.org/'			=> '../',
		'http://www.example.org/foo'		=> '../foo',
		'http://www.example.org/foo/bar'	=> '',
		'http://www.example.org/#hello'		=> '../#hello',
		'http://www.example.org/?query'		=> '../?query',
	);
	run_tests($base, \@REL_TESTS);
	confirm_tests($base, \@REL_TESTS);
};

subtest 'rel: scheme,host,path 2' => sub {
	my $base	= IRI->new(value => "http://xmlns.com/foaf/0.1/");
	my @REL_TESTS	= (
		'http://xmlns.com/foaf/0.1/name'	=> 'name',
	);
	run_tests($base, \@REL_TESTS);
	confirm_tests($base, \@REL_TESTS);
};

subtest 'tests derived from rfc3986 5.4.1' => sub {
	my $base	= IRI->new(value => "http://a/b/c/d;p?q");
	my @REL_TESTS	= (
		"g:h"					=> "g:h",
		"http://a/b/c/g"		=> "g",
		"http://a/b/c/g/"		=> "g/",
		"http://a/g"			=> "/g",
		"http://g"				=> "//g",
		"http://a/b/c/d;p?y"	=> "?y",
		"http://a/b/c/g?y"		=> "g?y",
		"http://a/b/c/d;p?q#s"	=> "#s",
		"http://a/b/c/g#s"		=> "g#s",
		"http://a/b/c/g?y#s"	=> "g?y#s",
		"http://a/b/c/;x"		=> ";x",
		"http://a/b/c/g;x"		=> "g;x",
		"http://a/b/c/g;x?y#s"	=> "g;x?y#s",
		"http://a/b/c/d;p?q"	=> "",
		"http://a/b/c/"			=> "./",
		"http://a/b/"			=> "../",
		"http://a/b/g"			=> "../g",
		"http://a/"				=> "../../",
		"http://a/g"			=> "/g",
	);
	run_tests($base, \@REL_TESTS);
	confirm_tests($base, \@REL_TESTS);
};

subtest 'rel: scheme,host,path,query' => sub {
	my $base	= IRI->new(value => "http://example.org/sparql?query=ASK%7B%7D%0A");
	my @REL_TESTS	= (
		'http://example.org/sparql#defaultGraph'	=> 'sparql#defaultGraph',
	);
	run_tests($base, \@REL_TESTS);
	confirm_tests($base, \@REL_TESTS);
};

done_testing();
