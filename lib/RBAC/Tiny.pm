package RBAC::Tiny;
# ABSTRACT: Tiny Role-Based Access Control (RBAC) implementation

use strict;
use warnings;
use Carp;
use List::Util;

sub new {
    my ( $class, %args ) = @_;
    my $raw_roles = $args{'roles'}
        or croak "'roles' attribute required";

    return bless { raw_roles => $raw_roles }, $class;
}

sub role {
    my ( $self, $role, $cache ) = @_;
    $cache ||= {};
    return $self->{'role'}{$role} ||= $self->_build_role( $role, $cache );
}

sub _build_role {
    my ( $self, $role, $cache ) = @_;
    my $raw = $self->{'raw_roles'}{$role}
        or croak "No data provided for role '$role'";

    $cache->{$role}
        and croak("Circular dependency detected in '$role' and '$cache->{$role}'");

    my @cans;
    # add all cans from parents, recursively
    foreach my $from ( @{ $raw->{'all_from'} || [] } ) {
        $self->{'raw_roles'}{$from}
            or croak("Role '$from' does not exist but used by '$role'");

        $cache->{$role} = $from;
        my $role = $self->role($from, $cache);
        push @cans, @{ $role->{'can'} || [] };
    }

    # add our own cans
    push @cans, @{ $raw->{'can'} || [] };

    my %can_cache;
    my %except = map +( $_ => 1 ), @{ $raw->{'except'} || [] };
    return {
        can => [
            grep +(
                !$except{$_} and !$can_cache{$_}++
            ), @cans
        ],
    };
}

sub can_role {
    my ( $self, $role, $permission ) = @_;
    List::Util::first { $_ eq $permission } @{ $self->role($role)->{'can'} };
}

sub roles {
    my $self = shift;
    return $self->{'roles'} ||= +{
        map +( $_ => $self->role($_) ), keys %{ $self->{'raw_roles'} }
    };
}

1;
