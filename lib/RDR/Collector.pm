package RDR::Collector;

use warnings;
use strict;
use IO::Select;
use IO::Socket;

=head1 NAME

RDR::Collector - Collect and Decodes RDRv1 packets

=head1 VERSION

Version 0.06

=cut

our $VERSION = '0.06';

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

        if ( !$self->{_GLOBAL}{'ServerIP'} )
                { die "ServerIP Required"; }

        if ( !$self->{_GLOBAL}{'ServerPort'} )
                { die "ServerPort Required"; }

        if ( !$self->{_GLOBAL}{'Timeout'} )
                { $self->{_GLOBAL}{'Timeout'}=5; }

        if ( !$self->{_GLOBAL}{'DataHandler'} )
                { die "DataHandler Function Must Be Defined"; }

	$self->{_GLOBAL}{'handles'}= \%handles;

	$self->{_GLOBAL}{'fields'} = fields_rdr( );
	$self->{_GLOBAL}{'field_types'} = field_types_rdr( );
	$self->{_GLOBAL}{'rdr_types'} = transpose_rdr_types( );
        return $self;
}

sub connect
{
my ( $self ) = shift;

# We need to add binding to specific addresses at
# some point.
# The new construct can slurp them in now anyway
# they are just ignored.

my $lsn = IO::Socket::INET->new
                        (
                        Listen    => 1024,
                        LocalAddr => $self->{_GLOBAL}{'ServerIP'},
                        LocalPort => $self->{_GLOBAL}{'ServerPort'},
                        ReuseAddr => 1,
                        Proto     => 'tcp',
                        Timeout    => $self->{_GLOBAL}{'Timeout'}
                        );
if (!$lsn)
        {
        $self->{_GLOBAL}{'STATUS'}="Failed to bind to address '".$self->{_GLOBAL}{'ServerIP'}."' ";;
        $self->{_GLOBAL}{'STATUS'}.="and port '".$self->{_GLOBAL}{'ServerPort'};
        $self->{_GLOBAL}{'ERROR'}=$!;
        return 0;
        }

$self->{_GLOBAL}{'Handle'} = $lsn;
$self->{_GLOBAL}{'Selector'}=new IO::Select( $lsn );
$self->{_GLOBAL}{'STATUS'}="Success Connected";
return 1;
}

sub return_status
{
my ( $self ) = shift;

return $self->{_GLOBAL}{'STATUS'};
}

sub return_error
{
my ( $self ) = shift;

return $self->{_GLOBAL}{'ERROR'};
}


sub get_data_segment
{
my ( $self ) = shift;
my ( $dataset ) ;

my ( $handles ) = $self->{_GLOBAL}{'handles'};
my ( $current_handles ) = $self->{_GLOBAL}{'ready_handles'};

my ( $fields ) = $self->{_GLOBAL}{'fields'};
my ( $field_types ) = $self->{_GLOBAL}{'field_types'};
my ( $rdr_types ) =  $self->{_GLOBAL}{'rdr_types'};


foreach my $handle ( @{$current_handles} )
        {
        if ( $handle==$self->{_GLOBAL}{'Handle'} )
                {
                my $new = $self->{_GLOBAL}{'Handle'}->accept;
                $self->{_GLOBAL}{'Selector'}->add($new);
                }
                else
                {
		my $blah;
		my $link= sysread($handle, $blah ,5);
		next if $link==0;
		if ( $link>0 )
                        {
			my ( $proc, $length ) = unpack ("CH8",$blah);
                       	$length = chr(hex(substr($length,0,2))).chr(hex(substr($length,2,2))).chr(hex(substr($length,4,2))).chr(hex(substr($length,6,2)));
			$length+=0; $link= sysread($handle, $blah ,$length );
			my ( $src, $dst, $src_port, $dst_port, $flow_id, $type,$fieldcount ) = unpack ("CCSSH8H8C",$blah );
                        $type = hex($type);
                        my %result;
			$self->extract_rdr(
                                        $type,
                                        $fieldcount,
                                        substr($blah, 15,length($blah)-15),
                                        \%result
                                        );
			$self->{_GLOBAL}{'DataHandler'}->(
					$self->{_GLOBAL},
					$handle->peerhost(),
					$handle->peerport(),
					\%result
						);
			undef %result;
                        }
                }
        }
return 1;
}


sub check_data_available
{
my ( $self ) = shift;

while ( $self->check_data_handles )
        { $self->get_data_segment(); }

$self->{_GLOBAL}{'STATUS'}="Socket Closed";
$self->{_GLOBAL}{'ERROR'}="Socket Closed";
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

my ( $fields ) = $self->{_GLOBAL}{'fields'};
my ( $field_types ) = $self->{_GLOBAL}{'field_types'};
my ( $rdr_types ) =  $self->{_GLOBAL}{'rdr_types'};

my ( $trans_fields );
my ( $name ) = ${$rdr_types}{$type};
if ( ${$fields}{$name} )
	{
	( $trans_fields )  = ${$fields}{$name};
	}

#my ( $name ) = ${$rdr_types}{$type};
#my ( $trans_fields )  = ${$fields}{$name};
if ( scalar(keys %{$trans_fields})> 0 )
        {
	${$pointer}{'RAWData'}=$data_block;
        for( $a=0;$a<scalar(keys %{$trans_fields});$a++ )
                {
                my ( $type, $length ) = unpack("CN",$data_block);
                my ( $real_type ) = ${$field_types}{$type};
                my ( $value ) = substr($data_block,5,$length);
                if ( ${$trans_fields}{$a}=~/\_ip$/i )
                        { $value = decode_type ( $real_type, $value ); $value = _IpIntToQuad($value); }
                if ( $real_type!~/^string$/i && ${$trans_fields}{$a}!~/\_ip$/i )
                        { $value = decode_type ( $real_type, $value ); }
                ${$pointer}{ ${$trans_fields}{$a} } = $value;
                $data_block = substr($data_block,$length+5,((length($data_block)-5)-$length));
                }
        }
	else
	{
	if ( ${$rdr_types}{$type} )
		{ $name = ${$rdr_types}{$type}; }
		else
		{ $name = $type; }
	my $field_count = 0;
	while ( length($data_block)> 0 )
		{
		my ( $type, $length ) = unpack("CN",$data_block);
		my ( $real_type ) = ${$field_types}{$type};
		my ( $value ) = substr($data_block,5,$length);
		if ( $real_type!~/^string$/i )
			{
			$value = decode_type ( $real_type, $value );
			}
		${$pointer}{ $field_count } = $value;
		$field_count++;
		$data_block = substr($data_block,$length+5,((length($data_block)-5)-$length));
		}
	}
${$pointer}{'RDR_Record'}=$name;
}

sub _IpIntToQuad { my($Int) = shift;
my($Ip1) = $Int & 0xFF; $Int >>= 8;
my($Ip2) = $Int & 0xFF; $Int >>= 8;
my($Ip3) = $Int & 0xFF; $Int >>= 8;
my($Ip4) = $Int & 0xFF; return("$Ip4.$Ip3.$Ip2.$Ip1");
}

sub decode_type
{
my ( $type ) = shift;
my ( $value ) = shift;
if ( $type=~/^int8$/i ) { return unpack("c",$value); }
if ( $type=~/^uint8$/i ) { return unpack("C",$value); }
if ( $type=~/^int16$/i ) { return unpack("S",$value); }
if ( $type=~/^uint16$/i ) { return unpack("S",$value); }
if ( $type=~/^int32$/i ) { return unpack("N",$value); }
if ( $type=~/^uint32$/i ) { return unpack("N",$value); }
if ( $type=~/^boolean$/i ) { return unpack("C",$value); }
return 1;
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

=head1 AUTHOR

Andrew S. Kennedy, C<< <shamrock at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-rdr-collector at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=RDR-Collector>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc RDR::Collector


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=RDR-Collector>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/RDR-Collector>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/RDR-Collector>

=item * Search CPAN

L<http://search.cpan.org/dist/RDR-Collector>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2008 Andrew S. Kennedy, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

1; # End of RDR::Collector
