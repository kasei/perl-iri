package IRI {
	use Moose;
	use v5.16;
	
	has 'value' => (is => 'ro', isa => 'Str', default => '');
	has 'base' => (is => 'ro', isa => 'IRI');
	has 'components' => (is => 'ro', writer => '_set_components');
	
	sub BUILD {
		my $self	= shift;
		my $comp	= $self->parse_components($self->value);
	}
	
	my $HEXDIG			= qr<[0-9A-F]>;
	my $ALPHA			= qr<[A-Za-z]>;
	my $subdelims		= qr<[!\$&'()*+,;=]>x;
	my $gendelims		= qr<[":/?#@] | \[ | \]>x;
	my $reserved		= qr<${gendelims} | ${subdelims}>;
	my $unreserved		= qr<${ALPHA} | [0-9] | [-._~]>x;
	my $pctencoded		= qr<%[A-Fa-f]{2}>;
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
	my $ipchar			= qr<${iunreserved}|${pctencoded}|${subdelims}|:|@>;
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
	sub parse_components {
		my $self	= shift;
		my $v		= shift;
		my $c;
		
		if ($v =~ /^${IRIreference}$/) {
			%$c = %+;
		} else {
			die "Not a valid IRI?";
		}
		
		$c->{path}	//= '';
		$self->_set_components($c);
	}
	
	sub scheme {
		my $self	= shift;
		return $self->components->{scheme};
	}
	
	sub host {
		my $self	= shift;
		return $self->components->{host};
	}
	
	sub port {
		my $self	= shift;
		return $self->components->{port};
	}
	
	sub user {
		my $self	= shift;
		return $self->components->{user};
	}
	
	sub path {
		my $self	= shift;
		return $self->components->{path};
	}
	
	sub fragment {
		my $self	= shift;
		return $self->components->{fragment};
	}
	
	sub query {
		my $self	= shift;
		return $self->components->{query};
	}
	
	sub merge {
		my $self	= shift;
		my $base	= shift;
		
		my $bc		= $base->components;
		my $c		= $self->components;
		if ($bc->{authority} and not($bc->{path})) {
			return "/" . $c->{path};
		} else {
			my $bp	= $bc->{path};
			my @pathParts	= split('/', $bp);
			pop(@pathParts);
			push(@pathParts, $c->{path});
			return join('/', @pathParts);
		}
	}

	sub removeDotSegments {
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
				my ($part, @parts)	= split('/', $input);
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

	sub abs {
		my $self	= shift;
		my $value	= $self->value;
		my $base	= $self->base;
		use Data::Dumper;
		if ($base and not($self->components->{scheme})) {
			# Resolve IRI relative to the base IRI
			my $v	= $self->value;
			my $bv	= $base->value;
			warn "resolving IRI <$v> relative to the base IRI <$bv>";
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
				if ($components{user} or $components{port} or $components{host}) {
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
							$target{path}	= $self->removeDotSegments($path);
						} else {
							my $path		= $self->merge($base);
							$target{path}	= $self->removeDotSegments($path);
						}
						if ($components{query}) {
							$target{query}	= $components{query};
						}
					}
					if ($base{user} or $base{port} or $base{host}) {
						foreach my $k (qw(user port host)) {
							if (exists $base{$k}) {
								$target{$k} = $base{$k};
							}
						}
					}
				}
				if ($base{scheme}) {
					$target{scheme} = $base{scheme};
				}
			}
			
			if ($components{fragment}) {
				$target{fragment}	= $components{fragment};
			}
			
			$value	= $self->string_from_components(%target);
		}
		return $value;
	}

	sub string_from_components {
		my $self		= shift;
		my %components	= @_;
		my $iri			= "";
		if (my $s = $components{scheme}) {
			$iri	.= "${s}:";
		}
		
		if ($components{user} or $components{port} or $components{host}) {
			# has authority
			$iri .= "//";
			if (my $u = $components{user}) {
				$iri	.= "${u}@";
			}
			if (my $h = $components{host}) {
				$iri	.= $h;
			}
			if (my $p = $components{port}) {
				$iri	.= ":$p";
			}
		}
		
		if (my $p = $components{path}) {
			$iri	.= $p;
		} else {
			warn "Cannot initialize an IRI with no path component.";
			return;
		}
		
		if (my $q = $components{query}) {
			$iri	.= "?$q";
		}
		
		if (my $f = $components{fragment}) {
			$iri	.= "#$f";
		}
		
		return $iri;
	}
}

1;

__END__




__END__

- (IRI*) initWithComponents: (NSDictionary*) components {
	if (self = [self init]) {
		NSMutableString* iri = [NSMutableString string];
		if (components[@"scheme"]) {
			[iri appendString:components[@"scheme"]];
			[iri appendString:@":"];
		}
		
		if (components[@"authority"]) {
			[iri appendString:@"//"];
			NSDictionary* auth	= components[@"authority"];
			//	[ iuserinfo "@" ] ihost [ ":" port ]
			NSMutableString* authority = [NSMutableString string];
			if (auth[@"user"]) {
				[authority appendString:auth[@"user"]];
				[authority appendString:@"@"];
			}
			[authority appendString:auth[@"host"]];
			if (auth[@"port"]) {
				[authority appendString:@":"];
				[authority appendString:auth[@"port"]];
			}
			[iri appendString:authority];
		}
		
		if (!components[@"path"]) {
			NSLog(@"Cannot initialize an IRI with no path component.");
			return nil;
		}
		[iri appendString:components[@"path"]];
		
		if (components[@"query"]) {
			[iri appendString:@"?"];
			[iri appendString:components[@"query"]];
		}

		if (components[@"fragment"]) {
			[iri appendString:@"#"];
			[iri appendString:components[@"fragment"]];
		}
		
		_components = components;
		_iriString	= iri;
		_baseIRI	= nil;
	}
	return self;
}




- (NSString *)absoluteString {
	if (_baseIRI && !_components[@"scheme"]) {
		// Resolve IRI relative to the base IRI
//		  NSLog(@"resolving IRI <%@> relative to the base IRI <%@>", _iriString, [_baseIRI absoluteString]);
		NSDictionary* components	= _components;
		NSDictionary* base			= [_baseIRI components];
//		  NSLog(@"base components: %@", base);
//		  NSLog(@"rel components: %@", components);
		NSMutableDictionary* target = [NSMutableDictionary dictionary];
		
		if (components[@"scheme"]) {
//			  NSLog(@"have scheme");
			target[@"scheme"]		= components[@"scheme"];
			target[@"authority"]	= components[@"authority"];
			target[@"path"]			= components[@"path"];	// TODO: should be remove_dots(components[@"path"])
			target[@"query"]		= components[@"query"];
		} else {
//			  NSLog(@"no scheme");
			if (components[@"authority"]) {
//				  NSLog(@"have authority");
				target[@"authority"]	= components[@"authority"];
				target[@"path"]			= components[@"path"];	// TODO: should be remove_dots(components[@"path"])
				target[@"query"]		= components[@"query"];
			} else {
//				  NSLog(@"no authority");
				if ([components[@"path"] isEqualToString:@""]) {
//					  NSLog(@"have path");
					target[@"path"] = base[@"path"];
					if (components[@"query"]) {
//						  NSLog(@"have query");
						target[@"query"]		= components[@"query"];
					} else {
//						  NSLog(@"no query");
						if (base[@"query"]) {
//							  NSLog(@"setting query from base");
							target[@"query"]		= base[@"query"];
						}
					}
				} else {
//					  NSLog(@"no path");
					if ([components[@"path"] hasPrefix:@"/"]) {
//						  NSLog(@"path has prefix /");
						target[@"path"]			= components[@"path"];	// TODO: should be remove_dots(components[@"path"])
					} else {
//						  NSLog(@"path without prefix /");
						target[@"path"] = [IRI pathByMergingBase:base withComponents:components];
						target[@"path"] = [IRI pathByRemovingDotSegmentsFromPath: target[@"path"]];
					}
					if (components[@"query"]) {
//						  NSLog(@"setting query from resource");
						target[@"query"]		= components[@"query"];
					}
				}
				if (base[@"authority"]) {
//					  NSLog(@"setting authority from base");
					target[@"authority"]		= base[@"authority"];
				}
			}
			if (base[@"scheme"]) {
//				  NSLog(@"setting scheme from base");
				target[@"scheme"]	= base[@"scheme"];
			}
		}
		if (components[@"fragment"]) {
//			  NSLog(@"setting fragment from resource");
			target[@"fragment"] = components[@"fragment"];
		}
		
		// TODO: re-combine the target components
		
//		  NSLog(@"target components: %@", target);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-value"
		[self initWithComponents:target];
#pragma clang diagnostic pop
	}
//	  NSLog(@"====> %@", _iriString);
	return _iriString;
}


#pragma mark -


