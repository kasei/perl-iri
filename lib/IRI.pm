=encoding utf8
	
=head1 NAME

IRI - Internationalized Resource Identifiers

=head1 VERSION

This document describes IRI version 0.002

=head1 SYNOPSIS

  use IRI;
  
  my $i	= IRI->new(value => 'https://example.org:80/index#frag');
  say $i->scheme; # 'https'
  say $i->path; # '/index'

  my $base = IRI->new(value => "http://www.hestebedg\x{e5}rd.dk/");
  my $i	= IRI->new(value => '#frag', base => $base);
  say $i->abs; # 'http://www.hestebedgård.dk/#frag'

=head1 DESCRIPTION

The IRI module provides an object representation for Internationalized
Resource Identifiers (IRIs) as defined by
L<RFC 3987|http://www.ietf.org/rfc/rfc3987.txt> and supports their parsing,
serializing, and base resolution.

=head1 METHODS

=over 4

=item C<< as_string >>

Returns the absolute IRI string resolved against the base IRI, if present;
the relative IRI string otherwise.

=item C<< abs >>

Returns the absolute IRI string (resolved against the base IRI if present).

=item C<< scheme >>

=item C<< host >>

=item C<< port >>

=item C<< user >>

=item C<< path >>

=item C<< fragment >>

=item C<< query >>

Returns the respective component of the parsed IRI.

=cut

package IRI 0.002 {
	use Moose;
	use Moose::Util::TypeConstraints;
	use v5.14;
	use warnings;
	
	class_type 'URI';
	coerce 'IRI' => from 'URI' => via { IRI->new( value => $_->as_string ) };

	has 'value' => (is => 'ro', isa => 'Str', default => '');
	has 'base' => (is => 'ro', isa => 'IRI', predicate => 'has_base', coerce => 1);
	has 'components' => (is => 'ro', writer => '_set_components');
	has 'as_string' => (is => 'ro', isa => 'Str', lazy => 1, builder => '_as_string');
	has 'abs' => (is => 'ro', lazy => 1, builder => '_abs');
	has 'resolved_components' => (
		is		=> 'ro',
		isa		=> 'HashRef',
		lazy	=> 1,
		builder	=> '_resolved_components',
		traits	=> ['Hash'],
		handles	=> {
			scheme		=>  [ accessor => 'scheme' ],
			host		=>  [ accessor => 'host' ],
			port		=>  [ accessor => 'port' ],
			user		=>  [ accessor => 'user' ],
			path		=>  [ accessor => 'path' ],
			fragment	=>  [ accessor => 'fragment' ],
			query		=>  [ accessor => 'query' ],
		},
	);

	around BUILDARGS => sub {
		my $orig 	= shift;
		my $class	= shift;
		if (scalar(@_) == 1) {
			return $class->$orig(value => shift);
		}
		return $class->$orig(@_);
	};
	
	sub BUILD {
		my $self	= shift;
		my $comp	= $self->_parse_components($self->value);
	}
	
	# These regexes are (mostly) from the syntax grammar in RFC 3987
	my $HEXDIG			= qr<[0-9A-F]>;
	my $ALPHA			= qr<[A-Za-z]>;
	my $subdelims		= qr<[!\$&'()*+,;=]>x;
	my $gendelims		= qr<[":/?#@] | \[ | \]>x;
	my $reserved		= qr<${gendelims} | ${subdelims}>;
	my $unreserved		= qr<${ALPHA} | [0-9] | [-._~]>x;
	my $pctencoded		= qr<%[0-9A-Fa-f]{2}>;
	my $decoctet		= qr<
							[0-9]			# 0-9
						|	[1-9][0-9]		# 10-99
						|	1 [0-9]{2}		# 100-199
						|	2 [0-4] [0-9]	# 200-249
						|	25 [0-5]		# 250-255
						>x;
	my $IPv4address		= qr<
							# IPv4address
							${decoctet}[.]${decoctet}[.]${decoctet}[.]${decoctet}
						>x;
	my $h16				= qr<${HEXDIG}{1,4}>;
	my $ls32			= qr<
							( ${h16} : ${h16} )
						|	${IPv4address}
						>x;
	my $IPv6address		= qr<
							# IPv6address
							(								 ( ${h16} : ){6} ${ls32})
						| (							  :: ( ${h16} : ){5} ${ls32})
						| ((					${h16} )? :: ( ${h16} : ){4} ${ls32})
						| (( ( ${h16} : ){,1} ${h16} )? :: ( ${h16} : ){3} ${ls32})
						| (( ( ${h16} : ){,2} ${h16} )? :: ( ${h16} : ){2} ${ls32})
						| (( ( ${h16} : ){,3} ${h16} )? ::   ${h16} :		 ${ls32})
						| (( ( ${h16} : ){,4} ${h16} )? ::				 ${ls32})
						| (( ( ${h16} : ){,5} ${h16} )? ::				 ${h16})
						| (( ( ${h16} : ){,6} ${h16} )? ::)
						>x;
	my $IPvFuture		= qr<v (${HEXDIG})+ [.] ( ${unreserved} | ${subdelims} | : )+>x;
	my $IPliteral		= qr<\[
							# IPliteral
							(${IPv6address} | ${IPvFuture})
							\]
						>x;
	my $port			= qr<(?<port>[0-9]*)>;
	my $scheme			= qr<(?<scheme>${ALPHA} ( ${ALPHA} | [0-9] | [+] | [-] | [.] )*)>x;
	my $iprivate		= qr<[\x{E000}-\x{F8FF}] | [\x{F0000}-\x{FFFFD}] | [\x{100000}-\x{10FFFD}]>x;
	my $ucschar			= qr<
							[\x{a0}-\x{d7ff}] | [\x{f900}-\x{fdcf}] | [\x{fdf0}-\x{ffef}]
						|	[\x{10000}-\x{1FFFD}] / [\x{20000}-\x{2FFFD}] / [\x{30000}-\x{3FFFD}]
						|	[\x{40000}-\x{4FFFD}] / [\x{50000}-\x{5FFFD}] / [\x{60000}-\x{6FFFD}]
						|	[\x{70000}-\x{7FFFD}] / [\x{80000}-\x{8FFFD}] / [\x{90000}-\x{9FFFD}]
						|	[\x{A0000}-\x{AFFFD}] / [\x{B0000}-\x{BFFFD}] / [\x{C0000}-\x{CFFFD}]
						|	[\x{D0000}-\x{DFFFD}] / [\x{E1000}-\x{EFFFD}]
						>x;
	my $iunreserved		= qr<${ALPHA}|[0-9]|[-._~]|${ucschar}>;
	my $ipchar			= qr<(${iunreserved})|(${pctencoded})|(${subdelims})|:|@>;
	my $ifragment		= qr<(?<fragment>(${ipchar}|/|[?])*)>;
	my $iquery			= qr<(?<query>(${ipchar}|${iprivate}|/|[?])*)>;
	my $isegmentnznc	= qr<(${iunreserved}|${pctencoded}|${subdelims}|@)+ # non-zero-length segment without any colon ":"
						>x;
	my $isegmentnz		= qr<${ipchar}+>;
	my $isegment		= qr<${ipchar}*>;
	my $ipathempty		= qr<>;
	my $ipathrootless	= qr<(?<path>${isegmentnz}(/${isegment})*)>;
	my $ipathnoscheme	= qr<(?<path>${isegmentnznc}(/${isegment})*)>;
	my $ipathabsolute	= qr<(?<path>/(${isegmentnz}(/${isegment})*)?)>;
	my $ipathabempty	= qr<(?<path>(/${isegment})*)>;
	my $ipath			= qr<
							${ipathabempty}		# begins with "/" or is empty
						|	${ipathabsolute}	# begins with "/" but not "//"
						|	${ipathnoscheme}	# begins with a non-colon segment
						|	${ipathrootless}	# begins with a segment
						|	${ipathempty}		# zero characters
						>x;
	my $iregname		= qr<(${iunreserved}|${pctencoded}|${subdelims})*>;
	my $ihost			= qr<(?<host>${IPliteral}|${IPv4address}|${iregname})>;
	my $iuserinfo		= qr<(?<user>(${iunreserved}|${pctencoded}|${subdelims}|:)*)>;
	my $iauthority		= qr<(${iuserinfo}@)?${ihost}(:${port})?>;
	my $irelativepart	= qr<
							(//${iauthority}${ipathabempty})
						|	${ipathabsolute}
						|	${ipathnoscheme}
						|	${ipathempty}
						>x;
	my $irelativeref	= qr<${irelativepart}([?]${iquery})?(#${ifragment})?>;
	my $ihierpart		= qr<(//${iauthority}${ipathabempty})|(${ipathabsolute})|(${ipathrootless})|(${ipathempty})>;
	my $absoluteIRI		= qr<${scheme}:${ihierpart}([?]${iquery})?>;
	my $IRI				= qr<${scheme}:${ihierpart}([?]${iquery})?(#${ifragment})?>;
	my $IRIreference	= qr<${IRI}|${irelativeref}>;
	sub _parse_components {
		my $self	= shift;
		my $v		= shift;
		my $c;
		
		if ($v =~ /^${IRIreference}$/) {
			%$c = %+;
		} else {
			die "Not a valid IRI? " . Dumper($v);
		}
		
		$c->{path}	//= '';
		$self->_set_components($c);
	}
	
	sub _merge {
		my $self	= shift;
		my $base	= shift;
		
		my $bc		= $base->components;
		my $c		= $self->components;
		my $base_has_authority	= ($bc->{user} or $bc->{port} or defined($bc->{host}));
		if ($base_has_authority and not($bc->{path})) {
			return "/" . $c->{path};
		} else {
			my $bp	= $bc->{path};
			my @pathParts	= split('/', $bp, -1);	# -1 limit means $path='/' splits into ('', '')
			pop(@pathParts);
			push(@pathParts, $c->{path});
			my $path	= join('/', @pathParts);
			return $path;
		}
	}

	sub _remove_dot_segments {
		my $self	= shift;
		my $input	= shift;
		my @output;
		while (length($input)) {
			if ($input =~ m<^[.][.]/>) {
				substr($input, 0, 3)	= '';
			} elsif ($input =~ m<^[.]/>) {
				substr($input, 0, 2)	= '';
			} elsif ($input =~ m<^/[.]/>) {
				substr($input, 0, 3)	= '/';
			} elsif ($input eq '/.') {
				$input	= '/';
			} elsif ($input =~ m<^/[.][.]/>) {
				substr($input, 0, 4)	= '/';
				pop(@output);
			} elsif ($input eq '/..') {
				$input	= '/';
				pop(@output);
			} elsif ($input eq '.') {
				$input	= '';
			} elsif ($input eq '..') {
				$input	= '';
			} else {
				my $leadingSlash	= ($input =~ m<^/>);
				if ($leadingSlash) {
					substr($input, 0, 1)	= '';
				}
				my ($part, @parts)	= split('/', $input, -1);
				$part	//= '';
				if (scalar(@parts)) {
					unshift(@parts, '');
				}
				$input	= join('/', @parts);
				if ($leadingSlash) {
					$part	= "/$part";
				}
				push(@output, $part);
			}
		}
		my $newPath = join('', @output);
		return $newPath;
	}

	sub _resolved_components {
		my $self	= shift;
		my $value	= $self->value;
		if ($self->has_base and not($self->components->{scheme})) {
			# Resolve IRI relative to the base IRI
			my $base	= $self->base;
			my $v		= $self->value;
			my $bv		= $base->value;
# 			warn "resolving IRI <$v> relative to the base IRI <$bv>";
			my %components	= %{ $self->components };
			my %base		= %{ $base->components };
			my %target;
			
			if ($components{scheme}) {
				foreach my $k (qw(scheme user port host path query)) {
					if (exists $components{$k}) {
						$target{$k} = $components{$k};
					}
				}
			} else {
				if ($components{user} or $components{port} or defined($components{host})) {
					foreach my $k (qw(scheme user port host path query)) {
						if (exists $components{$k}) {
							$target{$k} = $components{$k};
						}
					}
				} else {
					if ($components{path} eq '') {
						$target{path}	= $base{path};
						if ($components{query}) {
							$target{query}	= $components{query};
						} else {
							if ($base{query}) {
								$target{query}	= $base{query};
							}
						}
					} else {
						if ($components{path} =~ m<^/>) {
							my $path		= $components{path};
							$target{path}	= $self->_remove_dot_segments($path);
						} else {
							my $path		= $self->_merge($base);
							$target{path}	= $self->_remove_dot_segments($path);
						}
						if (defined($components{query})) {
							$target{query}	= $components{query};
						}
					}
					if ($base{user} or $base{port} or defined($base{host})) {
						foreach my $k (qw(user port host)) {
							if (exists $base{$k}) {
								$target{$k} = $base{$k};
							}
						}
					}
				}
				if (defined($base{scheme})) {
					$target{scheme} = $base{scheme};
				}
			}
			
			if (defined($components{fragment})) {
				$target{fragment}	= $components{fragment};
			}
			
			return \%target;
		}
		return $self->components;
	}
	
	sub _abs {
		my $self	= shift;
		my $value	= $self->_string_from_components( $self->resolved_components );
		return $value;
	}

	sub _as_string {
		my $self	= shift;
		if ($self->has_base) {
			return $self->abs;
		} else {
			return $self->value;
		}
	}
	
	sub _string_from_components {
		my $self		= shift;
		my $components	= shift;
		my $iri			= "";
		if (my $s = $components->{scheme}) {
			$iri	.= "${s}:";
		}
		
		if ($components->{user} or $components->{port} or defined($components->{host})) {
			# has authority
			$iri .= "//";
			if (my $u = $components->{user}) {
				$iri	.= "${u}@";
			}
			if (defined(my $h = $components->{host})) {
				$iri	.= $h // '';
			}
			if (my $p = $components->{port}) {
				$iri	.= ":$p";
			}
		}
		
		if (defined(my $p = $components->{path})) {
			$iri	.= $p;
		}
		
		if (defined(my $q = $components->{query})) {
			$iri	.= "?$q";
		}
		
		if (defined(my $f = $components->{fragment})) {
			$iri	.= "#$f";
		}
		
		return $iri;
	}
	
	__PACKAGE__->meta->make_immutable;
}

1;

__END__

=back

=head1 SEE ALSO

L<http://www.ietf.org/rfc/rfc3987.txt>

=head1 AUTHOR

Gregory Todd Williams  C<< <gwilliams@cpan.org> >>

=head1 COPYRIGHT

Copyright (c) 2014 Gregory Todd Williams. This
program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
