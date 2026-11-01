#!/usr/bin/perl
use strict;
use warnings;
no warnings 'redefine';
use Test::More;
use Data::Dumper;
use Try::Tiny;
use utf8;

use_ok( 'IRI' );

# resolve a relative IRI object back against its base and return the absolute string
sub _resolve_against_base {
	my ($rel, $base)	= @_;
	return IRI->new( value => $rel->value, base => $base )->abs;
}


{
	my $i;
	try {
		$i	= IRI->new(value => 'http://www.xn--orfolkedansere-rqb.dk/#8835/St%C3%A6vne%202013');
	} catch {
		diag $_;
	};
	isa_ok($i, 'IRI');
}

{
	my $base	= IRI->new( value => 'http://a.example/' );
	my $i		= IRI->new( value => 's', base => $base );
	isa_ok($i, 'IRI');
	is($i->abs, 'http://a.example/s');
}

{
	my $base	= IRI->new( value => 'http://a.example/' );
	my $i		= IRI->new( value => '#', base => $base );
	isa_ok($i, 'IRI');
	is($i->abs, 'http://a.example/#');
}

{
	my $base	= IRI->new( value => 'http://example.org/ns/' );
	my $i		= IRI->new( value => 'foo/', base => $base );
	isa_ok($i, 'IRI');
	is($i->abs, 'http://example.org/ns/foo/');
}

{
	my $i		= IRI->new( value => 'file:///Users/eve/data/bob.rdf' );
	isa_ok($i, 'IRI');
	is($i->abs, 'file:///Users/eve/data/bob.rdf');
}

{
	my $base	= IRI->new( value => 'file:///Users/eve/data/bob.rdf' );
	my $i		= IRI->new( value => '', base => $base );
	isa_ok($i, 'IRI');
	is($i->abs, 'file:///Users/eve/data/bob.rdf');
}

subtest '#11 - parsing codepoints beyond the basic multilingual plane fails due to typo in the IRI regexen' => sub {
	my $value	= 'http://hak.dbpedia.org/resource/Hàn_(𨧀)';
	my $i	= IRI->new( value => $value );
	isa_ok($i, 'IRI');
	is($i->abs, $value);
};

subtest 'trailing newline' => sub {
	my $value	= "http://example.org/foo/bar\n";
	eval { IRI->new( value => $value ) };
	ok( $@, 'IRI parsing expected failure' );
};

subtest 'set_query_param with $ and !' => sub {
	# Ensure that $ and ! are encoded in the query component.
	# Previous bug had mis-interpreted adjacent $! in the substitution pattern
	# as the error variable $!, resulting in no escaping.
	my $i	= IRI->new(value => "http://example.org/");
	my $j	= $i->set_query_param('foo', 'bar');
	is($j->value, 'http://example.org/?foo=bar');
	my $k	= $j->set_query_param('foo', 'a$!=b');
	is($k->value, 'http://example.org/?foo=a%24%21%3db');
};

subtest 'set_query_param on an IRI with no query' => sub {
	my $i	= IRI->new(value => 'http://example.org/path');
	my $j	= $i->set_query_param(a => 1);
	ok($j, 'returns a new object');
	is(eval { $j->value }, 'http://example.org/path?a=1');
};

subtest 'set_query_param has deterministic output' => sub {
	my $i	= IRI->new(value => 'http://example.org/');
	my $j	= $i->set_query_param(a => 1, b => 2, c => 3, d => 4, e => 5);
	is($j->value, 'http://example.org/?a=1&b=2&c=3&d=4&e=5');
};

subtest 'set_query_param preserves the base IRI' => sub {
	my $base	= IRI->new(value => 'http://example.org/p');
	my $i		= IRI->new(value => '?a=1', base => $base);
	my $j		= $i->set_query_param(b => 2);
	is($j->abs, 'http://example.org/p?a=1&b=2');
};

subtest 'query_form with "=" in values and keys without values' => sub {
	my $i	= IRI->new(value => 'http://example.org/?a=b=c&d&e=f');
	my @q	= $i->query_form;
	is_deeply(\@q, ['a', 'b=c', 'd', '', 'e', 'f']);
};

subtest 'set_query_param with "=" in values and keys without values' => sub {
	my $i	= IRI->new(value => 'http://example.org/?a=b%3Dc&d&e=f');
	my $j	= $i->set_query_param(g => 'h');
	my %q	= $j->query_form;
	is_deeply(\%q, { a => 'b=c', d => '', e => 'f', g => 'h' });
};

subtest 'false-but-defined components are serialized' => sub {
	is(IRI->new(value => 'http://h:0/')->abs, 'http://h:0/', 'port 0');
	is(IRI->new(value => 'http://0@h/')->abs, 'http://0@h/', 'user "0"');
	is(IRI->new(value => 'http://@h/')->abs, 'http://@h/', 'empty userinfo');
};

subtest 'IPv6 literal hosts with lowercase hex digits' => sub {
	foreach my $value ('http://[2001:db8::1]/', 'http://[::ffff:c000:280]/', 'http://[v1a.foo]/') {
		my $i	= eval { IRI->new(value => $value) };
		is($@, '', "parses $value");
		if ($i) {
			my ($host)	= ($value =~ m<(\[.*\])>);
			is($i->host, $host, 'host');
			is($i->abs, $value, 'abs');
		}
	}
};

subtest 'resolving a reference with an empty or "0" query' => sub {
	my $base	= IRI->new(value => 'http://a/b?q');
	is(IRI->new(value => '?', base => $base)->abs, 'http://a/b?', 'empty query');
	is(IRI->new(value => '?0', base => $base)->abs, 'http://a/b?0', 'query "0"');
	my $base0	= IRI->new(value => 'http://a/b?0');
	is(IRI->new(value => '', base => $base0)->abs, 'http://a/b?0', 'base query "0" inherited');
};

subtest 'authority is available after base resolution' => sub {
	my $base	= IRI->new(value => 'http://u@h:8/a');
	is(IRI->new(value => '/x', base => $base)->authority, 'u@h:8', 'inherited from base');
	is(IRI->new(value => '', base => $base)->authority, 'u@h:8', 'empty reference');
	is(IRI->new(value => '//other/x', base => $base)->authority, 'other', 'from reference');
};

subtest 'rel() with a colon in the first relative path segment' => sub {
	my $base	= IRI->new(value => 'http://ex/x/y');
	my $i		= IRI->new(value => 'http://ex/x/a:b');
	my $rel		= $i->rel($base);
	ok(not($rel->is_absolute), 'result is not parsed as an absolute IRI');
	is(_resolve_against_base($rel, $base), 'http://ex/x/a:b', 'resolves back to the original IRI');
};

subtest 'rel() when the base has a query and the target does not' => sub {
	my $base	= IRI->new(value => 'http://ex/a/?q');
	my $i		= IRI->new(value => 'http://ex/a/');
	my $rel		= $i->rel($base);
	is(_resolve_against_base($rel, $base), 'http://ex/a/', 'resolves back to the original IRI');
};

subtest 'rel() accepts a string base' => sub {
	my $rel	= eval { IRI->new(value => 'http://ex/x/z')->rel('http://ex/x/y') };
	is($@, '', 'does not die');
	is(eval { $rel->value }, 'z');
};

subtest 'rel() with a shared prefix, base with a query, rel with a fragment' => sub {
	my $base	= IRI->new(value => 'http://ex/x/y?foo=bar');
	my $i		= IRI->new(value => 'http://ex/x/y#frag');
	my $rel		= $i->rel($base);
	is($rel->value, "y#frag");
	is(_resolve_against_base($rel, $base), 'http://ex/x/y#frag', 'resolves back to the original IRI');
};

subtest 'base coercion of unsupported objects gives a useful error' => sub {
	eval { IRI->new(value => 'x', base => bless({}, 'Some::Other::Class'))->abs };
	my $err	= $@;
	ok($err, 'dies');
	unlike($err, qr/Value "" did not pass type constraint/, 'error is not an empty-string type failure');
	like($err, qr/Some::Other::Class/, 'error names the offending class');
};

subtest 'set_query_param encodes characters not allowed in an IRI' => sub {
	my $i	= IRI->new(value => 'http://example.org/?a=1');
	my $j	= eval { $i->set_query_param(b => 'x y') };
	is($@, '', 'value with a space does not die');
	ok($j, 'returns a new object');
	if ($j) {
		my %q	= $j->query_form;
		is($q{b}, 'x y', 'value round-trips through query_form');
		is($q{a}, '1', 'existing value preserved');
	}
};

subtest 'set_query_param percent-encodes non-ASCII characters as UTF-8 bytes' => sub {
	# These codepoints are above U+007F but are not ucschar/iprivate, so they
	# must be percent-encoded. Each %XX must be one byte of the UTF-8 encoding,
	# not the codepoint number (which would produce e.g. "%ffff" for U+FFFF).
	my $i	= IRI->new(value => 'http://example.org/');
	is($i->set_query_param(k => "\x{85}")->value, 'http://example.org/?k=%c2%85', 'U+0085 (C1 control)');
	is($i->set_query_param(k => "\x{FFFF}")->value, 'http://example.org/?k=%ef%bf%bf', 'U+FFFF (noncharacter)');
	is($i->set_query_param(k => "\x{FDD0}")->value, 'http://example.org/?k=%ef%b7%90', 'U+FDD0 (noncharacter)');
};

done_testing();
