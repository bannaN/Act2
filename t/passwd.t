use Data::Dumper;

use Test::More tests => 15;

use strict;
use warnings;
use Encode;
use_ok('Act::Util::Password');



{ #Check that we are able to generate a salt
  my $salt = Act::Util::Password::gen_salt();
  ok($salt, "Salt is generated");
}
{
  #Check that we get the correct amount of bits
  diag "Generating 500 salt hashes";
  my @salts = ();
  for(my $i = 0; $i < 500; $i++){
    push @salts, Act::Util::Password::gen_salt();
  }
  diag "Checking that all salts are 32 bytes";
  my $success = 1;
  for my $salt (@salts){
    if(length(Encode::encode_utf8($salt)) != 32){
      $success = 0;
      diag "Salt" . $salt . " is not 32 bytes (256 bits)";
    }
  }
  ok($success, "All salts are 32 bytes");
}
{ #Check that we can generate a password
 
  diag "Generating 500 passwords";
  my @passwords = ();
  for(my $i = 0; $i < 500; $i++){
    push @passwords, Act::Util::Password::gen_password();
  }
  ok(scalar(@passwords) == 500, "Got 500 passwords");
  
  #Checking that all passwords has length > 10
  my $success = 1;
  foreach my $pass (@passwords){
    if (length($pass) < 10) {
      $success = 0;
      diag "Password " . $pass . " length is < 10";
    }
    
  }
  ok($success, "All passwords have length > 10");
}
{ #Check the legacy crypt method
  my $secret = "The quick brown fox jumps over the lazy dog 1234567890 !@#$%&";
  my $hash = Act::Util::Password::crypt_legacy_password($secret);
  ok($hash, "md5sum generated");
  ok(
    $hash eq Act::Util::Password::crypt_legacy_password($secret),
    "Just to check that noone edits the old method to use salts etc"
  );
}
{ #Test the new crypt method
  
  
  #The salt is chosen by a fair diceroll
  my @data = (
    #Secret, salt, iterations, result
    ['The quick brown fox jumps over the lazy dog 1234567890 !@#$%&', 'acftpdfoUurW4$xV8lO8aZn&sT1do85j', 10000, 'KGeI9UamzzddR6qWyff/dIoYdtEZF2QUq0LEQEcsZUY='],
    ['The quick brown fox jumps over the lazy dog 1234567890 !@#$%&', 'acftpdfoUurW4$xV8lO8aZn&sT1do85j', 10001, '0UCsBjMiS2CLnjylG/d0WQFA8efTLLQPqqWXnJsa7+o='],
    ['The quick brown fox jumps over the lazy dog 1234567890', 'acftpdfoUurW4axV8lO8aZnrsT1do85j', 10000, 'tYVzahtcncRDXAUxjxcDfIJEAjB0Ayg2T92NhQi2WuY='],
    ['secret', 'acftpdfoUurW4axV8lO8aZnasT1do85j', 10000, 'T+OTr0HigDW4vTIM4kxM3H5ehOewND3u4WBAI8tBvgI=']
  );
  

  foreach my $set (@data){
    #Unpacking
    my ($secret, $salt, $iterations, $known) = @{ $set };
    my $hash = Act::Util::Password::crypt_password($secret, $salt, $iterations);
    cmp_ok(
      $hash,'eq', $known,
      '$secret hashed to ' . $known 
    );
  }
  
  

}
{ #Test that we are not able to call crypt_password with no or empty salt
  
  my $died = undef;
  eval{
    Act::Util::Password::crypt_password('asdf'); #No salt
  };
  if ($@) { $died = $@;}
  
  ok(
    $died
    && lc($died) =~ /invalid salt/, "crypt_password died with a invalid salt message");
  
  $died = undef;
  
  eval{
    Act::Util::Password::crypt_password('asdf', ''); #Empty salt
  };
  if ($@) { $died = $@;}
  
  ok(
    $died
    && lc($died) =~ /invalid salt/, "crypt_password died with a invalid salt message");  
}
{ #Test that we will die on an empty or invalid password
  
  my $died = undef;
  eval{
    Act::Util::Password::crypt_password('', 'invalidsalt'); #empty password
  };
  if ($@) { $died = $@;}
  
  ok(
    $died
    && lc($died) =~ /invalid password/, "crypt_password died with a invalid password message");
  
  $died = undef;
  
  eval{
    Act::Util::Password::crypt_password(undef, 'invalidsalt'); #no password
  };
  if ($@) { $died = $@;}
  
  ok(
    $died
    && lc($died) =~ /invalid password/, "crypt_password died with a invalid password message");  
}



