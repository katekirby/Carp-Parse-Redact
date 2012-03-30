use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
	module_name          => 'Carp::Parse::Redact',
	license              => 'artistic',
	dist_author          =>
	[
		'Guillaume Aubert <aubertg@cpan.org>',
		'Kate Kirby <kate@cpan.org>',
	],
	dist_version_from    => 'lib/Carp/Parse/Redact.pm',
	build_requires       =>
	{
		'Carp'                 => 0,
		'Carp::Parse'          => 0,
		'Data::Dump'           => 0,
		'Test::Deep'           => 0,
		'Test::Exception'      => 0,
		'Test::More'           => 0,
		'Data::Validate::Type' => 0,
	},
	requires             =>
	{
		'perl'            => 5.006,
	},
	add_to_cleanup       =>
	[
		'Carp-Parse-Redact-*',
	],
	create_makefile_pl   => 'traditional',
	recursive_test_files => 1,
);

$builder->create_build_script();
