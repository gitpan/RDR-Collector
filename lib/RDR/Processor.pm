package RDR::Processor;

use warnings;
use strict;
use IO::Select;
use IO::Socket;

=head1 NAME

RDR::Processor - Decodes RDRv1 packets

=head1 VERSION

Version 0.071

=cut

our $VERSION = '0.071';

=head1 SYNOPSIS

=head1 EXPORT

None

=head1 FUNCTIONS

=head2 function1

=cut

sub new {

        my $self = {};
        bless $self;

	my ( %handles );

        my ( $class , $attr ) =@_;

        $self->{_GLOBAL}{'DEBUG'}=0;

        while (my($field, $val) = splice(@{$attr}, 0, 2))
                { $self->{_GLOBAL}{$field}=$val; }

        $self->{_GLOBAL}{'STATUS'}="OK";

        if ( !$self->{_GLOBAL}{'VendorID'} )
                { $self->{_GLOBAL}{'VendorID'}="Generic Client"; }

        if ( !$self->{_GLOBAL}{'DataHandler'} )
                { die "DataHandler Function Must Be Defined"; }

        if ( !$self->{_GLOBAL}{'Filename'} )
                { die "Filename Must Be Defined"; }

	if ( $self->{_GLOBAL}{'ProtocolFile'} )
		{
		if ( !open(__FILE,"<".$self->{_GLOBAL}{'ProtocolFile'})	)
			{
			die "ProtocolFile specified, but not found.";
			exit(0);
			}
		close (__FILE);
		$self->{_GLOBAL}{'protocol_ids'} = load_protocol_file ( $self->{_GLOBAL}{'ProtocolFile'} );
		}
		else
		{
		$self->{_GLOBAL}{'protocol_ids'} = { } ;
		}

	$self->{_GLOBAL}{'fields'} = fields_rdr( );
	$self->{_GLOBAL}{'field_types'} = field_types_rdr( );
	$self->{_GLOBAL}{'rdr_types'} = transpose_rdr_types( );
        return $self;
}

sub load_protocol_file
{
my ( $filename ) = shift;
my %protocol_results;
open (__FILE,"<$filename");
while (<__FILE>)
	{
	$_=~s/^\s*//; $_=~ s/\s*$//;
	my ( $protocol_name, $protocol_number );
	( $protocol_name, $protocol_number ) = ( split( /,/,$_) )[0,1];
	$protocol_results{$protocol_number} = $protocol_name;
	}
close (__FILE);
return \%protocol_results;
}

sub return_error
{
my ( $self ) = shift;

return $self->{_GLOBAL}{'ERROR'};
}

sub process_file
{
my ( $self ) = shift;
my ( $filename ) = $self->{_GLOBAL}{'Filename'};

if ( !$filename )
	{
	exit(0);
	}

my ( $handler_file );

if ( !open ($handler_file,"<$filename") )
	{
	exit(0);
	}
	
# This is a little hacky, but works

my $buffer;
my $buffer2;
my $buffer3;
my $remainder="";

while ( ( my $len = sysread ( $handler_file,$buffer, 5 )) > 0 )
        {
        $buffer = $remainder.$buffer;
        $remainder="";
        my ( $proc ) = unpack ("C",$buffer );
        my ( $length ) = substr($buffer,1,4);
        $length = hex(substr($length,0,1)).hex(substr($length,1,1)).hex(substr($length,2,1)).hex(substr($length,3,1));
        my $len2 = sysread ( $handler_file, $buffer2, $length ) ;
        if ( $len2!=$length )
                {
                print "Failed to read full record.\n";
                next;
                }
        $buffer3= $buffer.$buffer2;
        $remainder=$self->check_data_available($buffer3);
        }

close ($handler_file);

return 1;
}


sub convert_chars_value
{
# this is just crazy stuff. Is PERL suited to this stuff, not really.
# This is a safety handler for the RDR Packets as *sometimes* they are
# full of crap.
my ($length) = @_;
my $char1;
my $char2;
my $char3;
my $char4;
my $failed=0;

#print "Conversion is '".ord(substr($length,0,1))."' '".ord(substr($length,1,1))."' '".ord(substr($length,2,1))."' '".ord(substr($length,3,1))."'\n";

if ( (ord(substr($length,1,1))>=48 && ord(substr($length,1,1))<=57) ||
	(ord(substr($length,1,1))>=65 && ord(substr($length,1,1))<=70) )
	{
	$char2 = hex(substr($length,1,1));
	}	
	else
	{
	$failed=1;
	}

if ( (ord(substr($length,0,1))>=48 && ord(substr($length,0,1))<=57) ||
	(ord(substr($length,0,1))>=65 && ord(substr($length,0,1))<=70) )
	{
	$char1 = hex(substr($length,0,1));
	}
	else
	{
	$failed=1;
	}	

if ( (ord(substr($length,2,1))>=48 && ord(substr($length,2,1))<=57) ||
	(ord(substr($length,2,1))>=65 && ord(substr($length,2,1))<=70) )
	{
	$char3 = hex(substr($length,2,1));
	}
	else
	{
	$failed=1;
	}
		

if ( (ord(substr($length,3,1))>=48 && ord(substr($length,3,1))<=57) ||
	(ord(substr($length,3,1))>=65 && ord(substr($length,3,1))<=70) )
	{
	$char4 = hex(substr($length,3,1));
	}
	else
	{
	$failed=1;
	}	

if ( $failed==1 )
	{
	return "DEAD";
	}
	else
	{
	return $char1.$char2.$char3.$char4;
	}
}

sub get_data_segment
{
my ( $self ) = shift;
my ( $dataset ) = shift;

my ( $fields ) = $self->{_GLOBAL}{'fields'};
my ( $field_types ) = $self->{_GLOBAL}{'field_types'};
my ( $rdr_types ) =  $self->{_GLOBAL}{'rdr_types'};

#print "Dataset length is '".length($dataset)."'\n";

if ( length($dataset)<15 )
	{
	#print "Skipping data set here.\n";
	return "";
	}

my ( $proc ) = unpack ("C",$dataset);

my ( $length ) = substr($dataset,1,4);

return "" if !$length;

if ( length($length)<4 )
	{
	#print "Length should be 4 it is '".length($length)."'\n";
	return "";
	}

$length = convert_chars_value ( $length );

#$length = hex(substr($length,0,1)).hex(substr($length,1,1)).hex(substr($length,2,1)).hex(substr($length,3,1));
if ( $length=~/^dead/i )
	{
	#print "Bad length found length is '$length'.\n";
	return "";
	}

$length+=1;
#print "Dataset length is '".length($dataset)."'\n";

$dataset = substr( $dataset,5,length($dataset)-5 );

#print "Dataset length is '".length($dataset)."'\n";

my ( $src, $dst, $src_port, $dst_port, $flow_id, $type,$fieldcount ) = unpack ("CCSSH8H8C",$dataset );

#print "src '$src' dst '$dst' src_port '$src_port' dst_port '$dst_port' flow id '$flow_id' type '$type' fieldcount '$fieldcount'\n";
$type = hex($type);
my %result;
my $return_value="";

if ( length($dataset)>=15 )
	{
$return_value = $self->extract_rdr(
	$type,
	$fieldcount,
	substr($dataset, 15,length($dataset)-15),
	\%result
	);

$self->{_GLOBAL}{'DataHandler'}->(
	$self->{_GLOBAL},
	"localprocessor",
	"localprocessor",
	\%result
	);
	}
undef %result;

#print "Remaining return value is '".length($return_value)."'\n";

return $return_value;
}


sub check_data_available
{
my ( $self ) = shift;
my ( $data_segment ) = shift;

my $remaining = $self->get_data_segment( $data_segment );

#print "Remaining data set is '".length($remaining)."'\n";

return $remaining;

}


sub check_data_handles
{
my ( $self ) = shift;
my ( @handle ) = $self->{_GLOBAL}{'Selector'}->can_read;
$self->{_GLOBAL}{'ready_handles'}=\@handle;
}


sub extract_rdr
{
my ( $self ) = shift;
my ( $type ) = shift;
my ( $count ) = shift;
my ( $data_block ) = shift;
my ( $pointer ) = shift;

return "" if !$data_block;

my ( $fields ) = $self->{_GLOBAL}{'fields'};
my ( $field_types ) = $self->{_GLOBAL}{'field_types'};
my ( $rdr_types ) =  $self->{_GLOBAL}{'rdr_types'};
my ( $protocol_ids ) = $self->{_GLOBAL}{'protocol_ids'};

my ( $trans_fields );
my ( $name ) = ${$rdr_types}{$type};
if ( !$name )
	{
	#print "RDR type not found was '$type'\n";
	return "";
	}
if ( ${$fields}{$name} )
	{
	#print "Name is '$name'\n";
	( $trans_fields )  = ${$fields}{$name};
	}

#return unless $name=~/^SubscriberUsage$/i;

#print "Size of keys is '".scalar(keys %{$trans_fields})."'\n";

#print "RDR name is '$name'\n";

if ( scalar(keys %{$trans_fields})> 0 )
        {
        for( $a=0;$a<scalar(keys %{$trans_fields});$a++ )
                {
		#next if length($data_block)<5;
		my ( $block_start ) = substr( $data_block,0,5);

		#print "Length of block_start is '".length($block_start)."'\n";

                my ( $type, $data_length ) = unpack("CN",$block_start);

		#print "Type is '$type' length is '$data_length'\n";

		my ( $current_block ) = substr($data_block,5,$data_length);

		if ( length($data_block)>=($data_length+5) )
			{
			$data_block = substr($data_block,$data_length+5,length($data_block)-($data_length+5));
			}
			else
			{
			next;
			}

		if ( !$type )
			{
			#print "Type not found was '$type'.\n";
			next; 
			}

		if ( !${$field_types}{$type} )
        		{
		        #print "RDR field not found was '$type' count was '$a' max is '".scalar(keys %{$trans_fields})."'\n";
			#print "Length is '$data_length'\n";
			if ( length($current_block)<$data_length )
				{
				next;
				}
			}

                my ( $real_type ) = ${$field_types}{$type};

		#print "Name is '".${$trans_fields}{$a}."' length is '".$data_length."'\n";

		if ( !$real_type ) 
			{
			#print "Real type failed with '$real_type'\n";
			}

		#print "Type was '$type' Real type was '$real_type' \n";

                my ( $value ) = substr($current_block,0,$data_length);

                if ( ${$trans_fields}{$a}=~/\_ip$/i )
                        { $value = decode_type ( $name, $real_type, $value, ${$trans_fields}{$a} ); $value = _IpIntToQuad($value); }

		if ( ${$trans_fields}{$a}=~/\_mac$/i )
			{ $value = $self->convert_mac_address ( $value ); }

                if ( ${$trans_fields}{$a}!~/\_ip$/i && ${$trans_fields}{$a}!~/\_mac$/ )
                        { 
			$value = decode_type ( $name, $real_type, $value, ${$trans_fields}{$a} ); 
			}

		if ( $value=~/^dead/i )
                        {
                        #print "Value was DEAD return outbound.\n";
                       # return $data_block;
			${$pointer}{ ${$trans_fields}{$a} } ="DEAD";
			next;
                        }


#        	if ( ${$trans_fields}{$a}=~/\_mac$/i )
#                	{ $value = $self->convert_mac_address ( $value ); }

		if ( ${$trans_fields}{$a}=~/^protocol_id$/i )
			{
			my $protocol_id_found = ${$protocol_ids}{$value};
			if ( !$protocol_id_found )
				{
				$value = $value."(".$value.")";
				}
				else
				{
				$value = $protocol_id_found."(".$value.")";
				}
			}


                ${$pointer}{ ${$trans_fields}{$a} } = $value;
		#next if length($data_block)<($data_length+5);
                }
        }
	else
	{
	#print "RDR record is just plain broken or unknown.\n";
	}
${$pointer}{'RDR_Record'}=$name;
return "";
}

sub _IpIntToQuad { my($Int) = shift;
if (!$Int) { return "0.0.0.0"; }
my($Ip1) = $Int & 0xFF; $Int >>= 8;
my($Ip2) = $Int & 0xFF; $Int >>= 8;
my($Ip3) = $Int & 0xFF; $Int >>= 8;
my($Ip4) = $Int & 0xFF; return("$Ip4.$Ip3.$Ip2.$Ip1");
}

sub decode_type
{
my ( $rdr_name ) = shift;
my ( $type ) = shift;
my ( $value ) = shift;
my ( $field_name ) = shift;

my ( $return_value );

#print "Decoder running for RDR '$rdr_name' fieldname '$field_name' type '$type' value is ";

if ( !$value ) { return 1; }
if ( !$type ) { return 1; }
if ( $type=~/^int8$/i ) { $return_value = unpack("c",$value); }
if ( $type=~/^uint8$/i ) { $return_value = unpack("C",$value); }

# this is just crazy
if ( $type=~/^int16$/i ) {
        # now we should just have 2 bytes, so swap them and decode as s
        # this is slow as you like, but hey thats life !!!
        my $byte1  = substr($value,0,1);
        my $byte2  = substr($value,1,1);
        my $done = $byte2.$byte1;
        $return_value = unpack("s",$done);
        }

# this is now correct
if ( $type=~/^uint16$/i ) {
        $return_value = unpack("n",$value);
        }

# more crazy stuff
if ( $type=~/^int32$/i )  {
        # this needs all four bytes changing in order
        my $byte1 = substr($value,0,1);
        my $byte2 = substr($value,1,1);
        my $byte3 = substr($value,2,1);
        my $byte4 = substr($value,3,1);
        my $done = $byte4.$byte3.$byte2.$byte1;
        $return_value = unpack("l",$done);
        }

# back to being normal
if ( $type=~/^uint32$/i ) { $return_value = unpack("N",$value); }

if ( $type=~/^float$/i ) { $return_value = unpack("f",$value); }
if ( $type=~/^boolean$/i ) { $return_value = unpack("C",$value); }

if ( $type=~/^string$/i ) {
	if ( length($value)==0 )
		{
		$return_value="";
		}
	 if ( $value!~/^[0-9\.a-zA-Z\\|\s\@\_\/\?\&\=\%\+\-,\^\:\[\]\{\}\$\"\;\<\>\*\~\£]+$/ && length($value)>0 )
		{
		#print "actual value before death was '$value' length '".length($value)."'\n";
		$return_value ="DEAD";
		}
		else
		{
		$return_value = $value;
		}
	}

if ( !$return_value ) { $return_value=0; }

#print "Mapped value was '".$return_value."'\n";

return $return_value;
}

sub fields_rdr
{
my ( %rdr_fields )
                = (
                        'HTTPTransaction' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'protocol_id',
                                        4 => 'skipped_sessions',
                                        5 => 'server_ip',
                                        6 => 'server_port',
                                        7 => 'access_string',
                                        8 => 'info_string',
                                        9 => 'client_ip',
                                        10 => 'client_port',
                                        11 => 'initiating_side',
                                        12 => 'report_time',
                                        13 => 'millisec_duration',
                                        14 => 'time_frame',
                                        15 => 'session_upstream_volume',
                                        16 => 'session_downstream_volume',
                                        17 => 'subscriber_counter_id',
                                        18 => 'global_counter_id',
                                        19 => 'package_counter_id',
                                        20 => 'ip_protocol',
                                        21 => 'protocol_signature',
                                        22 => 'zone_id',
                                        23 => 'flavor_id',
                                        24 => 'flow_close_mode',
                                        25 => 'user_agent',
                                        26 => 'http_url'
                                },
                        'RTSPTransaction' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'protocol_id',
                                        4 => 'skipped_sessions',
                                        5 => 'server_ip',
                                        6 => 'server_port',
                                        7 => 'access_string',
                                        8 => 'info_string',
                                        9 => 'client_ip',
                                        10 => 'client_port',
                                        11 => 'initiating_side',
                                        12 => 'report_time',
                                        13 => 'millisec_duration',
                                        14 => 'time_frame',
                                        15 => 'session_upstream_volume',
                                        16 => 'session_downstream_volume',
                                        17 => 'subscriber_counter_id',
                                        18 => 'global_counter_id',
                                        19 => 'package_counter_id',
                                        20 => 'ip_protocol',
                                        21 => 'protocol_signature',
                                        22 => 'zone_id',
                                        23 => 'flavor_id',
                                        24 => 'flow_close_mode',
                                        25 => 'rtsp_session_id',
                                        26 => 'rtsp_url',
                                        27 => 'response_date',
                                        28 => 'total_encoding_rate',
                                        29 => 'number_of_video_streams',
                                        30 => 'number_of_audio_streams',
                                        31 => 'session_title',
                                        32 => 'server_name'
                                },
                        'VoIPTransaction' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'protocol_id',
                                        4 => 'skipped_sessions',
                                        5 => 'server_ip',
                                        6 => 'server_port',
                                        7 => 'access_string',
                                        8 => 'info_string',
                                        9 => 'client_ip',
                                        10 => 'client_port',
                                        11 => 'initiating_side',
                                        12 => 'report_time',
                                        13 => 'millisec_duration',
                                        14 => 'time_frame',
                                        15 => 'session_upstream_volume',
                                        16 => 'session_downstream_volume',
                                        17 => 'subscriber_counter_id',
                                        18 => 'global_counter_id',
                                        19 => 'package_counter_id',
                                        20 => 'ip_protocol',
                                        21 => 'protocol_signature',
                                        22 => 'zone_id',
                                        23 => 'flavor_id',
                                        24 => 'flow_close_mode',
                                        25 => 'application_id',
                                        26 => 'upstream_packet_loss',
                                        27 => 'downstream_packet_loss',
                                        28 => 'upstream_average_jitter',
                                        29 => 'downstream_average_jitter',
                                        30 => 'call_destination',
                                        31 => 'call_source',
                                        32 => 'upstream_payload_type',
                                        33 => 'downstream_payload_type',
                                        34 => 'call-type',
                                        35 => 'media_channels'
                                },
                        'SubscriberUsage' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_usage_counter_id',
                                        3 => 'breach_state',
                                        4 => 'reason',
                                        5 => 'configured_duration',
                                        6 => 'duration',
                                        7 => 'end_time',
                                        8 => 'upstream_volume',
                                        9 => 'downstream_volume',
                                        10 => 'sessions',
                                        11 => 'seconds'
                                },
                        'Transaction' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'protocol_id',
                                        4 => 'skipped_sessions',
                                        5 => 'server_ip',
                                        6 => 'server_port',
                                        7 => 'access_string',
                                        8 => 'info_string',
                                        9 => 'client_ip',
                                        10 => 'client_port',
                                        11 => 'initiating_side',
                                        12 => 'report_time',
                                        13 => 'millisec_duration',
                                        14 => 'time_frame',
                                        15 => 'session_upstream_volume',
                                        16 => 'session_downstream_volume',
                                        17 => 'subscriber_counter_id',
                                        18 => 'global_counter_id',
                                        19 => 'package_counter_id',
                                        20 => 'ip_protocol',
                                        21 => 'protocol_signature',
                                        22 => 'zone_id',
                                        23 => 'flavour_id',
                                        24 => 'flow_close_mode'
                                },
                        'TransactionUsage' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'protocol_id',
                                        4 => 'skipped_sessions',
                                        5 => 'server_ip',
                                        6 => 'server_port',
                                        7 => 'access_string',
                                        8 => 'info_string',
                                        9 => 'client_ip',
                                        10 => 'client_port',
                                        11 => 'initiating_side',
                                        12 => 'report_time',
                                        13 => 'millisec_duration',
                                        14 => 'time_frame',
                                        15 => 'session_upstream_volume',
                                        16 => 'session_downstream_volume',
                                        17 => 'subscriber_counter_id',
                                        18 => 'global_counter_id',
                                        19 => 'package_counter_id',
                                        20 => 'ip_protocol',
                                        21 => 'protocol_signature',
                                        22 => 'zone_id',
                                        23 => 'flavor_id',
                                        24 => 'flow_close_mode'
                                },
                        'RealTimeSubscriberUsage' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_usage_counter_id',
                                        3 => 'aggregation_object_id',
                                        4 => 'breach_state',
                                        5 => 'reason',
                                        6 => 'configured_duration',
                                        7 => 'duration',
                                        8 => 'end_time',
                                        9 => 'upstream_volume',
                                        10 => 'downstream_volume',
                                        11 => 'sessions',
                                        12 => 'seconds'
                                },
                        'LinkUsage' =>
                                {
                                        0 => 'link_id',
                                        1 => 'generator_id',
                                        2 => 'service_usage_counter_id',
                                        3 => 'configured_duration',
                                        4 => 'duration',
                                        5 => 'end_time',
                                        6 => 'upstream_volume',
                                        7 => 'downstream_volume',
                                        8 => 'sessions',
                                        9 => 'seconds',
                                        10 => 'concurrent_sessions',
                                        11 => 'active_subscribers',
                                        12 => 'total_active_subscribers'
                                },
                        'PackageUsage' =>
                                {
                                        0 => 'package_counter_id',
                                        1 => 'generator_id',
                                        2 => 'service_usage_counter_id',
                                        3 => 'configured_duration',
                                        4 => 'duration',
                                        5 => 'end_time',
                                        6 => 'upstream_volume',
                                        7 => 'downstream_volume',
                                        8 => 'sessions',
                                        9 => 'seconds',
                                        10 => 'concurrent_sessions',
                                        11 => 'active_subscribers',
                                        12 => 'total_active_subscribers'
                                },
                        'VirtualLink' =>
                                {
                                        0 => 'vlink_id',
                                        1 => 'vlink_direction',
                                        2 => 'generator_id',
                                        3 => 'service_usage_counter_id',
                                        4 => 'configured_duration',
                                        5 => 'duration',
                                        6 => 'end_time',
                                        7 => 'upstream_volume',
                                        8 => 'downstream_volume',
                                        9 => 'sessions',
                                        10 => 'seconds',
                                        11 => 'concurrent_sessions',
                                        12 => 'active_subscribers',
                                        13 => 'total_active_subscribers'
                                },
                        'Blocking' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'protocol_id',
                                        4 => 'client_ip',
                                        5 => 'client_port',
                                        6 => 'server_ip',
                                        7 => 'server_port',
                                        8 => 'initiating_side',
                                        9 => 'access_string',
                                        10 => 'info_string',
                                        11 => 'block_reason',
                                        12 => 'block_rdr_count',
                                        13 => 'redirected',
                                        14 => 'report_time'
                                },
                        'QuotaBreach' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'bucket_id',
                                        3 => 'end_time',
                                        4 => 'bucket_quota',
                                        5 => 'aggregaton_period_type'
                                },
                        'RemainingQuota' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'rdr_reason',
                                        3 => 'end_time',
                                        4 => 'remaining_quota_1',
                                        5 => 'remaining_quota_2',
                                        6 => 'remaining_quota_3',
                                        7 => 'remaining_quota_4',
                                        8 => 'remaining_quota_5',
                                        9 => 'remaining_quota_6',
                                        10 => 'remaining_quota_7',
                                        11 => 'remaining_quota_8',
                                        12 => 'remaining_quota_9',
                                        13 => 'remaining_quota_10',
                                        14 => 'remaining_quota_11',
                                        15 => 'remaining_quota_12',
                                        16 => 'remaining_quota_13',
                                        17 => 'remaining_quota_14',
                                        18 => 'remaining_quota_15',
                                        19 => 'remaining_quota_16'
                                },
                        'QuotaThreshold' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'bucket_id',
                                        3 => 'global_threshold',
                                        4 => 'end_time',
                                        5 => 'bucket_quota'
                                },
                        'QuotaStateRestore' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'rdr_reason',
                                        3 => 'end_time'
                                },
                        'DHCP' =>
                                {
                                        0 => 'cpe_mac',
                                        1 => 'cmts_ip',
                                        2 => 'assigned_ip',
                                        3 => 'released_ip',
                                        4 => 'transaction_id',
                                        5 => 'message_type',
                                        6 => 'option_type_0',
                                        7 => 'option_type_1',
                                        8 => 'option_type_2',
                                        9 => 'option_type_3',
                                        10 => 'option_type_4',
                                        11 => 'option_type_5',
                                        12 => 'option_type_6',
                                        13 => 'option_type_7',
                                        14 => 'option_type_0',
                                        15 => 'option_type_1',
                                        16 => 'option_type_2',
                                        17 => 'option_type_3',
                                        18 => 'option_type_4',
                                        19 => 'option_type_5',
                                        20 => 'option_type_6',
                                        21 => 'option_type_7',
                                        22 => 'end_time'
                                },
                        'RADIUS' =>
                                {
                                        0 => 'server_ip',
                                        1 => 'server_port',
                                        2 => 'client_ip',
                                        3 => 'client_port',
                                        4 => 'initiating_side',
                                        5 => 'radius_packet_code',
                                        6 => 'radius_id',
                                        7 => 'attribute_value_1',
                                        8 => 'attribute_value_2',
                                        9 => 'attribute_value_3',
                                        10 => 'attribute_value_4',
                                        11 => 'attribute_value_5',
                                        12 => 'attribute_value_6',
                                        13 => 'attribute_value_7',
                                        14 => 'attribute_value_8',
                                        15 => 'attribute_value_9',
                                        16 => 'attribute_value_10',
                                        17 => 'attribute_value_11',
                                        18 => 'attribute_value_12',
                                        19 => 'attribute_value_13',
                                        20 => 'attribute_value_14',
                                        21 => 'attribute_value_15',
                                        22 => 'attribute_value_16',
                                        23 => 'attribute_value_17',
                                        24 => 'attribute_value_18',
                                        25 => 'attribute_value_19',
                                        26 => 'attribute_value_20',
                                        27 => 'end_time'
                                },
                        'FlowStart' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'ip_protocol',
                                        4 => 'server_ip',
                                        5 => 'server_port',
                                        6 => 'client_ip',
                                        7 => 'client_port',
                                        8 => 'initiating_side',
                                        9 => 'start_time',
                                        10 => 'report_time',
                                        11 => 'breach_state',
                                        12 => 'flow_id',
                                        13 => 'generator_id'
                                },
                        'FlowEnd' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'ip_protocol',
                                        4 => 'server_ip',
                                        5 => 'server_port',
                                        6 => 'client_ip',
                                        7 => 'client_port',
                                        8 => 'initiating_side',
                                        9 => 'start_time',
                                        10 => 'report_time',
                                        11 => 'breach_state',
                                        12 => 'flow_id',
                                        13 => 'generator_id'
                                },
                        'FlowOnGoing' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'ip_protocol',
                                        4 => 'server_ip',
                                        5 => 'server_port',
                                        6 => 'client_ip',
                                        7 => 'client_port',
                                        8 => 'initiating_side',
                                        9 => 'start_time',
                                        10 => 'report_time',
                                        11 => 'breach_state',
                                        12 => 'flow_id',
                                        13 => 'generator_id'
                                },
                        'MediaFlow' =>
                                {
                                        0 => 'subscriber_id',
                                        1 => 'package_id',
                                        2 => 'service_id',
                                        3 => 'protocol_id',
                                        4 => 'destination_ip',
                                        5 => 'destination_port',
                                        6 => 'source_ip',
                                        7 => 'source_port',
                                        8 => 'initiating_side',
                                        9 => 'zone_id',
                                        10 => 'flavor_id',
                                        11 => 'sip_domain',
                                        12 => 'sip_user_agent',
                                        13 => 'start_time',
                                        14 => 'report_time',
                                        15 => 'duration_seconds',
                                        16 => 'upstream_volume',
                                        17 => 'downstream_volume',
                                        18 => 'ip_protocol',
                                        19 => 'flow_type',
                                        20 => 'session_id',
                                        21 => 'upstream_jitter',
                                        22 => 'downstream_jitter',
                                        23 => 'upstream_packet_loss',
                                        24 => 'downstream_packet_loss',
                                        25 => 'upstream_payload_type',
                                        26 => 'downstream_payload_type'
                                },
                        'AttackStart' =>
                                {
                                        0 => 'attack_id',
                                        1 => 'subscriber_id',
                                        2 => 'attacking_ip',
                                        3 => 'attacked_ip',
                                        4 => 'attacked_port',
                                        5 => 'attacking_side',
                                        6 => 'ip_protocol',
                                        7 => 'attack_type',
                                        8 => 'generator_id',
                                        9 => 'attack_time',
                                        10 => 'report_time'
                                },
                        'AttackEnd' =>
                                {
                                        0 => 'attack_id',
                                        1 => 'subscriber_id',
                                        2 => 'attacking_ip',
                                        3 => 'attacked_ip',
                                        4 => 'attacked_port',
                                        5 => 'attacking_side',
                                        6 => 'ip_protocol',
                                        7 => 'attack_type',
                                        8 => 'generator_id',
                                        9 => 'attack_time',
                                        10 => 'report_time'
                                }
                        );
return \%rdr_fields;
}

sub field_types_rdr
{
my ( %rdr_types )
                =
                (
                11 => 'INT8',
                12 => 'INT16',
                13 => 'INT32',
                14 => 'UINT8',
                15 => 'UINT16',
                16 => 'UINT32',
		21 => 'FLOAT',
                31 => 'BOOLEAM',
                41 => 'STRING'
                );

return \%rdr_types;
}

sub transpose_rdr_types
{
my ( %rdr_values ) = (
        '4042321920' => 'SubscriberUsage',
        '4042321922' => 'RealTimeSubscriberUsage',
        '4042321924' => 'PackageUsage',
        '4042321925' => 'LinkUsage',
        '4042321926' => 'VirtualLink',
        '4042321936' => 'Transaction',
        '4042323000' => 'TransactionUsage',
        '4042323004' => 'HTTPTransaction',
        '4042323008' => 'RTSPTransaction',
        '4042323050' => 'VoIPTransaction',
        '4042321984' => 'Blocking',
        '4042321954' => 'QuotaBreach',
        '4042321968' => 'RemainingQuota',
        '4042321969' => 'QuotaThreshold',
        '4042321970' => 'QuotaStateRestore',
        '4042321987' => 'Radius',
        '4042321986' => 'DHCP',
        '4042321942' => 'FlowStart',
        '4042321944' => 'FlowEnd',
        '4042323052' => 'MediaFlow',
        '4042321943' => 'FlowOnGoing',
        '4042321945' => 'AttackStart',
        '4042321946' => 'AttackEnd',
        '4042322000' => 'MaliciousTraffic',
	'8456'	     => 'PrivateOne',
	'77771'	     => 'PrivateTwo',
	'77775'      => 'PrivateThree',
	'77776'      => 'PrivateFour',
	'1000000'    => 'PrivateFive',
	'11110001'   => 'PrivateSix',
	'11110002'   => 'PrivateSeven',
	'11110003'   => 'PrivateEight',
	'11110004'   => 'PrivateNine',
	'11111001'   => 'PrivateTen',
	'11120001'   => 'PrivateEleven',
	'11140001'   => 'PrivateTwelve',
	'11150001'   => 'PrivateThirteen',
	'11160001'   => 'PrivateFourteen',
	'11170001'   => 'PrivateFifteen',
	'4294967295' => 'TestRDR'

        );
return \%rdr_values;
}

sub convert_mac_address
{
my ( $self ) = shift;
my ( $raw_input) = shift;
return "" if !$raw_input;
my ( $char1, $char2, $char3, $char4, $char5, $char6) = unpack ('CCCCCC', $raw_input);
$char1=sprintf ("%#.2x",$char1); $char1=(split(/0x/,$char1))[1] if $char1=~/x/g;
$char2=sprintf ("%#.2x",$char2); $char2=(split(/0x/,$char2))[1] if $char2=~/x/g;
$char3=sprintf ("%#.2x",$char3); $char3=(split(/0x/,$char3))[1] if $char3=~/x/g;
$char4=sprintf ("%#.2x",$char4); $char4=(split(/0x/,$char4))[1] if $char4=~/x/g;
$char5=sprintf ("%#.2x",$char5); $char5=(split(/0x/,$char5))[1] if $char5=~/x/g;
$char6=sprintf ("%#.2x",$char6); $char6=(split(/0x/,$char6))[1] if $char6=~/x/g;
return ("$char1$char2.$char3$char4.$char5$char6");
}


=head1 AUTHOR

Andrew S. Kennedy, C<< <shamrock at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-rdr-collector at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=RDR-Processor>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc RDR::Processor


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=RDR-Processor>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/RDR-Processor>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/RDR-Processor>

=item * Search CPAN

L<http://search.cpan.org/dist/RDR-Processor>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2008 Andrew S. Kennedy, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

1; # End of RDR::Processor
