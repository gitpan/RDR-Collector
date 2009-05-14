package RDR::Collector;

use warnings;
use strict;
use IO::Select;
use IO::Socket;

=head1 NAME

RDR::Collector - Collect RDRv1 packets

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

        if ( !$self->{_GLOBAL}{'ServerIP'} )
                { die "ServerIP Required"; }

        if ( !$self->{_GLOBAL}{'ServerPort'} )
                { die "ServerPort Required"; }

        if ( !$self->{_GLOBAL}{'Timeout'} )
                { $self->{_GLOBAL}{'Timeout'}=5; }

        if ( !$self->{_GLOBAL}{'DataHandler'} )
                { die "DataHandler Function Must Be Defined"; }

	$self->{_GLOBAL}{'handles'}= \%handles;

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

foreach my $handle ( @{$current_handles} )
        {
        if ( $handle==$self->{_GLOBAL}{'Handle'} )
                {
                my $new = $self->{_GLOBAL}{'Handle'}->accept;
                $self->{_GLOBAL}{'Selector'}->add($new);
		#print "Connection established.\n";
                }
                else
                {
		my $blah;
		my $link= sysread($handle, $blah ,1024);
		if ( $link==0 )
			{
                        delete ${$handles}{$handle};
                        $self->{_GLOBAL}{'Selector'}->remove($handle);
			$handle->close();
			}
		if ( $link>0 )
                        {
			$self->{_GLOBAL}{'DataHandler'}->(
					$self->{_GLOBAL},
					$handle->peerhost(),
					$handle->peerport(),
					$blah
						);
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
