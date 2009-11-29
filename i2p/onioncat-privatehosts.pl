#!/usr/bin/perl
#
# Reads hosts.txt and generates a file which can be used as privatehosts.txt
# for the I2P router to convert GarliCat-IDs back to the original key.
#
# The original hostname, full IPV6 address, and b32 name are included as a
# comment for each host.
#
# See below for perl package requirements.
#
# zzz 1/08 public domain
#

use strict;
use CGI qw(:standard);
use MIME::Base64;
use Convert::Base32;
use Digest::SHA qw(sha256);
use Digest::SHA qw(sha256_hex);

my $hosthash;

# load the whole db into memory
sub loadhosts
{
   my $hostcount = 0;
   open(local *STATLIST, "hosts.txt") or die "Can't access hosts.txt!";
   while (<STATLIST>) {
      my $name;
      my $key;
      my $restofline;
      ($name,$restofline) = split(/=/);
      $key = $restofline;
      $name = lc($name);
      chomp($key);
      $hosthash->{$name} = $key;
      $hostcount++;
   }
   close STATLIST;
}


sub printhosts
{
   my @sorted = keys %$hosthash;
   my $name;
   foreach $name (@sorted) {
      my $b64 = $hosthash->{$name};
      $b64 =~ s/-/+/g;
      $b64 =~ s/~/\//g;
      my $decoded = decode_base64($b64);
      my $hash=sha256($decoded);
      my $hexhash = sha256_hex($decoded);
      my $encoded = encode_base32($hash);
      print "#" . $name . " fd60:db4d:ddb5";
      for (my $i = 0; $i < 20; $i += 4) {
         printf(":%s", substr($hexhash, $i, 4));
      }
      print " " . $encoded . ".b32.i2p\n";
      print substr($encoded, 0, 16) . ".oc.b32.i2p=" . $hosthash->{$name} . "\n";
   }
   return 0;
}

loadhosts();
printhosts();

