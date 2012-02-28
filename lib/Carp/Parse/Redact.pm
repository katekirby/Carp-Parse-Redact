package Carp::Parse::Redact;

use warnings;
use strict;

use Carp;
use Carp::Parse;
use Carp::Parse::CallerInformation::Redacted;


=head1 NAME

Carp::Parse::Redact - Parse a Carp stack trace into an array of caller information, while redacting sensitive function parameters out.


=head1 DESCRIPTION

Carp produces a stacktrace that includes caller arguments; this module parses
each line of the stack trace to extract its arguments and redacts out the
sensitive information contained in the function arguments for each caller.


=head1 VERSION

Version 1.0.1

=cut

our $VERSION = '1.0.1';


=head1 ARGUMENTS REDACTED BY DEFAULT

By default, this module will redact values for which the argument name is:

=over 4

=item * password

=item * passwd

=item * cc_number

=item * cc_exp

=item * ccv

=back

You can easily change this list when parsing a stack trace by passing the
argument I<sensitive_argument_names> when calling C<parse_stack_trace()>.

=cut

my $DEFAULT_ARGUMENTS_REDACTED =
[
	qw(
		password
		passwd
		cc_number
		cc_exp
		ccv
	)
];


=head1 SYNOPSIS

	# Retrieve a Carp stack trace with longmess(). This is tedious, but you will
	# normally be using this module in a context where the stacktrace is already
	# generated for you and you want to parse it, so you won't have to go through
	# this step.
	sub test3 { return Carp::longmess("Test"); }
	sub test2 { return test3(); }
	sub test1 { return test2(); }
	my $stack_trace = test1();
	
	# Parse the Carp stack trace.
	# The call takes an optional list of arguments to redact, if you don't want
	# to use the default.
	use Carp::Parse::Redact;
	my $parsed_stack_trace = Carp::Parse::Redact::parse_stack_trace(
		$stack_trace,
		sensitive_argument_names => #optional
		[
			password
			passwd
			cc_number
			cc_exp
			ccv
		],
	);
	
	use Data::Dump qw( dump );
	foreach my $caller_information ( @$parsed_stack_trace )
	{
		# Print the arguments for each caller.
		say dump( $caller->get_redacted_arguments_list() );
	}


=head1 FUNCTIONS

=head2 parse_stack_trace()

Parse a stack trace produced by C<Carp> into an arrayref of
C<Carp::Parse::CallerInformation::Redacted> objects and redact out the sensitive
information from each function caller arguments.

	my $redacted_parsed_stack_trace = Carp::Parse::Redact::parse_stack_trace( $stack_trace );

=cut

sub parse_stack_trace
{
	my ( $stack_trace, %args ) = @_;
	
	# Verify parameters.
	my $sensitive_argument_names = delete( $args{'sensitive_argument_names'} );
	croak "'sensitive_argument_names' must be an arrayref"
		if defined( $sensitive_argument_names ) && !UNIVERSAL::isa( $sensitive_argument_names, 'ARRAY' ); ## no critic (BuiltinFunctions::ProhibitUniversalIsa)
	croak "The following parameters are not supported: " . Data::Dump::dump( %args )
		if scalar( keys %args ) != 0;
	
	# Make a hash of arguments to redact.
	my $arguments_redacted =
	{
		map { $_ => 1 }
		@{ $sensitive_argument_names || $DEFAULT_ARGUMENTS_REDACTED }
	};
	
	# Get the parsed stack trace from Carp::Parse.
	my $parsed_stack_trace = Carp::Parse::parse_stack_trace( $stack_trace );
	
	# Redact sensitive information here.
	my $redacted_parsed_stack_trace = [];
	foreach my $caller_information ( @{ $parsed_stack_trace || [] } )
	{
		my $redact_next = 0;
		my $redacted_arguments_list = [];
		foreach my $argument ( @{ $caller_information->get_arguments_list() || [] } )
		{
			if ( $redact_next )
			{
				push( @$redacted_arguments_list, '[redacted]' );
				$redact_next = 0;
			}
			else
			{
				push( @$redacted_arguments_list, $argument );
				$redact_next = 1 if defined( $argument ) && $arguments_redacted->{ $argument };
			}
		}
		
		push(
			@$redacted_parsed_stack_trace,
			Carp::Parse::CallerInformation::Redacted->new(
				{
					arguments_string        => $caller_information->get_arguments_string(),
					arguments_list          => $caller_information->get_arguments_list(),
					redacted_arguments_list => $redacted_arguments_list,
					line                    => $caller_information->get_line(),
				},
			),
		);
	}
	
	return $redacted_parsed_stack_trace;
}


=head1 AUTHOR

Kate Kirby, C<< <kate at cpan.org> >>.

Guillaume Aubert, C<< <aubertg at cpan.org> >>.


=head1 BUGS

Please report any bugs or feature requests to C<bug-carp-parse-redact at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Carp-Parse-Redact>. 
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

	perldoc Carp::Parse::Redact


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Carp-Parse-Redact>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Carp-Parse-Redact>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Carp-Parse-Redact>

=item * Search CPAN

L<http://search.cpan.org/dist/Carp-Parse-Redact/>

=back


=head1 ACKNOWLEDGEMENTS

Thanks to ThinkGeek (L<http://www.thinkgeek.com/>) and its corporate overlords
at Geeknet (L<http://www.geek.net/>), for footing the bill while we eat pizza
and write code for them!


=head1 COPYRIGHT & LICENSE

Copyright 2012 Kate Kirby & Guillaume Aubert.

This program is free software; you can redistribute it and/or modify it
under the terms of the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1;
