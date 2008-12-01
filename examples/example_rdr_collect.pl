#!/usr/local/bin/perl

use strict;
use RDR::Collector;

# This is an example wrapper script to collect/process RDR records
#
# This has been tested with 12000 RDR records per second receive rate
# however this did not include any interaction with a database/logging
# service.

my $rdr_client = new RDR::Collector(
			[
			ServerIP => '10.1.1.1'
			ServerPort => '33000',
			Timeout => 2,
			DataHandler => \&display_data
			]
			);

# Setup the local RDR listener
my $status = $rdr_client->connect();

# If we could not listen tell us why.
if ( !$status )
	{
	print "Status was '".$rdr_client->return_status()."'\n";
	print "Error was '".$rdr_client->return_error()."'\n";
	exit(0);
	}

# Now just wait for RDR data.
$rdr_client->check_data_available();

exit(0);

# This routine is called from DataHandler when the module
# instance is initialised.
# 4 parameters are returned, internal ref, remote IP, remote Port and 
# a pointer to a hash with key/value pairs of the RDR record.
sub display_data
{
my ( $glob ) = shift;
my ( $remote_ip ) = shift;
my ( $remote_port ) = shift;
my ( $data ) = shift;

# This code prints out all elements, except the raw RDR data,
# passed to the data pointer. It is commented out and is really only
# here for demonstration purposes.
my $attribute_line;
my $data_line;
foreach my $attribute ( sort { $a<=> $b } keys %{$data} )
	{
	next if $attribute=~/^rawdata/i;
	print "attribute '$attribute' value '${$data}{$attribute}'\n";
	}

}

