package Act::Handler::Payment::List;
use strict;
use Apache::Constants qw(NOT_FOUND);
use Act::Config;
use Act::Order;
use Act::Template::HTML;
use Act::User;

sub handler
{
    # for treasurers only
    unless ($Request{user} && $Request{user}->is_treasurer) {
        $Request{status} = NOT_FOUND;
        return;
    }
    # retrieve users and their payment info
    my $users = Act::User->get_items();
    my %orders;
    for my $u (@$users) {
        $orders{$u->user_id} = Act::Order->new(
            user_id  => $u->user_id,
            conf_id  => $Request{conference},
            status   => 'paid',
        );
    }
    # set/unset invoice_ok
    if ($Request{args}{ok}) {
        for my $o (grep defined($_), values %orders) {
            if ($o->invoice_ok && !$Request{args}{$o->order_id}) {
                $o->update(invoice_ok => 0);
            }
            elsif (!$o->invoice_ok && $Request{args}{$o->order_id}) {
                $o->update(invoice_ok => 1);
            }
        }
    }
    # process the template
    my $template = Act::Template::HTML->new();
    $template->variables(
        users => [ sort {
                            lc $a->last_name  cmp lc $b->last_name
                         || lc $a->first_name cmp lc $b->first_name
                        }
                   @$users
                 ],
        orders => \%orders,
        
    ); 
    $template->process('payment/list');
}

1;
__END__

=head1 NAME

Act::Handler::Payment::List - show all payments

=head1 DESCRIPTION

See F<DEVDOC> for a complete discussion on handlers.

=cut