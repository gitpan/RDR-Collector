#!/usr/local/bin/perl

use strict;
use RDR::Collector;
use IO::File;

my $handle;

# This is an example wrapper script to collect/process RDR records
#
# This has been tested with 12000 RDR records per second receive rate
# however this did not include any interaction with a database/logging
# service.

my $date=`date +%Y_%m_%d_%H_%M`;chop($date);

my $handle = IO::File->new("/rdr/data_records_final_$date\_only_raw","w");

my $rdr_client = new RDR::Collector(
			[
			ServerIP => '192.168.1.1',
			ServerPort => '10000',
			Timeout => 2,
			FileHandle => $handle,
			DataHandler => \&collect_data
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
# the raw data
sub collect_data
{
my ( $glob ) = shift;
my ( $remote_ip ) = shift;
my ( $remote_port ) = shift;
my ( $data ) = shift;

my $handle = ${$glob}{'FileHandle'};

# This code prints out the raw data to the file.

print $handle $data;

}

