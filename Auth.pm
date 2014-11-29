package Act::Auth;

use strict;
use Apache::AuthCookie;
use Apache::Constants qw(OK);
use Digest::MD5 ();
use Crypt::PBKDF2;


use Act::Config;
use Act::User;
use Act::Util;

use base qw(Apache::AuthCookie);

sub access_handler ($$)
{
    my ($self, $r) = @_;

    # set correct login script url
    $r->dir_config(ActLoginScript => join('/', '', $Request{conference}, 'login'));

    # disable authentication unless required
    # (Apache doesn't let us do it the other way around)
    if ($Request{private}) {

        # don't recognize_user
        $r->set_handlers(PerlFixupHandler  => [\&OK]);
    }
    else {
        $r->set_handlers(PerlAuthenHandler => [\&OK]);
    }
    return OK;
}
sub authen_cred ($$\@)
{
    my ($self, $r, $login, $sent_pw, $remember_me) = @_;

    # error message prefix
    my $prefix = join ' ', map { "[$_]" }
        $r->server->server_hostname,
        $r->connection->remote_ip,
        $login;

    # remove leading and trailing spaces
    for ($login, $sent_pw) {
        s/^\s*//;
        s/\s*$//;
    }

    # login and password must be provided
    $login   or do { $r->log_error("$prefix No login name"); return undef; };
    $sent_pw or do { $r->log_error("$prefix No password");   return undef; };

    # search for this user in our database
    my $user = Act::User->new( login => lc $login );
    $user or do { $r->log_error("$prefix Unknown user"); return undef; };

    
    my $b64digest;
    
    if ($user->{salt}) {
        $r->log_error("inside pbkdf2");
        #If the user has a defined salt he is using the new PBKDF2 algorithm
        my $iterations = ($user->{iterations}) ? $user->{iterations} : 10000;
        my $pbkdf2 = Crypt::PBKDF2->new(
            hash_class => 'HMACSHA256',
            iterations => $iterations,
            salt_len => 4, #32bits
        );
        
        $b64digest = $pbkdf2->PBKDF2_base64($user->{salt}, $sent_pw);
    }else{
        $r->log_error("inside md5sum");
        #User is on the old Digest::MD5 method =/
        my $digest = Digest::MD5->new;
        $digest->add(lc $sent_pw);
        $b64digest = $digest->b64digest();
    }
    $r->log_error("b64digest: " . $b64digest );
    
    #Just make sure the $b64digest AND the users password isnt empty for some stupid reason
    if ($b64digest eq '' || $user->{passwd} eq '') {
        $r->log_error("Either digest or passwd is empty. Refusing login");
        return undef;
    }
    
    
    if ($b64digest eq $user->{passwd}) {
        # user is authenticated - create a session
        my $sid = Act::Util::create_session($user);
    
        # remember remember me
        $r->pnotes(remember_me => $remember_me);
        return $sid;        
    }else{
        $r->log_error("$prefix Bad password");
        return undef;
    }
    
    #Kindof a catch all. Default behaviour should be to reject login
    $r->log_error("$prefix Login rejected");
    return undef;
}

sub authen_ses_key ($$$)
{
    my ($self, $r, $sid) = @_;

    # search for this user in our database
    my $user = Act::User->new( session_id => $sid );

    # unknown session id
    return () unless $user;

    # save this user for the content handler
    $Request{user} = $user;
    _update_language();

    return ($user->{login});
}

sub send_cookie
{
    my ($self, $ses_key, $cookie_args) = @_;
    my $r = Apache->request();

    # add expiration date if "remember me" was checked
    # unless an expiration is already set (logout)
    if (   !($cookie_args && exists $cookie_args->{expires})
        && $r->pnotes('remember_me') )
    {
        $cookie_args ||= {};
        $cookie_args->{expires} = '+6M';
    }
    $self->SUPER::send_cookie($ses_key, $cookie_args);
}

sub _update_language
{
    $Request{user}->update(language => $Request{language})
      if $Request{language} && $Request{user}->language ne $Request{language};
}

1;
__END__

=head1 NAME

Act::Auth - authentication handler and callbacks

=head1 SYNOPSIS

See F<INSTALL> and F<conf/httpd.conf>

=cut
