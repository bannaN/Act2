package Act::Util::Password;

use strict;
use warnings;
use utf8;
use Crypt::Random qw(makerandom makerandom_itv);
use Crypt::PBKDF2;
use Crypt::PBKDF2::Hash::HMACSHA2;
use Digest::MD5;

my @generate_passwd_chars = (
  1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  '!', '@', '#', '$', '%', '&', '?', '='
);

my $DEFAULT_ITERATIONS = 10000;

#Choosen by several fair dicerolls
#http://xkcd.com/221/
#Cation changing this will invalidate all passwords
#and break the tests
my $PEPPER = "PLxJo1nI1cfqGKXitW1X";

sub get_num_passwd_iterations{
  return $DEFAULT_ITERATIONS;
}

sub gen_salt{
  my $salt; 
  for(my $i = 0; $i < 32; $i++){
    $salt .= $generate_passwd_chars[
      makerandom_itv(
        Lower => 0,
        Upper => scalar( @generate_passwd_chars )
      )
    ];
  }
  if (!defined $salt || $salt eq ''){ die("Generated invalid salt"); }
  return $salt;
}

sub gen_password
{
  my $lower = 10;
  my $upper = 20;
  my $length = makerandom_itv(
    Lower => $lower,
    Upper => $upper
  );
  
  #Generate the new password
  my $passwd;
  for(my $i = 0; $i < $length; $i++){
    $passwd .= $generate_passwd_chars[
      makerandom_itv(
        Lower => 0,
        Upper => scalar( @generate_passwd_chars )
      )
    ];
  }
  #Make sure we return a valid password
  if (length($passwd) < $lower){ die("generated password is to short"); }
  return $passwd;
}

sub crypt_legacy_password
{
  my $digest = Digest::MD5->new;
  $digest->add(shift);
  return $digest->b64digest();
}
sub crypt_password
{
  my ($passwd, $salt, $iterations) = @_;

  if (!defined $passwd || $passwd eq ''){ die("Invalid password"); }
  if (!defined $salt || $salt eq ''){ die("Invalid salt"); }
  
  if (!defined $iterations || $iterations == 0){ $iterations = $DEFAULT_ITERATIONS; }
  
  my $pbkdf2 = Crypt::PBKDF2->new(
    hash_class => 'HMACSHA2',
    iterations => $iterations,
    salt_len => 32, #256bits
  );
  return $pbkdf2->PBKDF2_base64($salt, $PEPPER.$passwd);
}
1;

__END__