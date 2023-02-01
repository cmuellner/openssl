#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";
use riscv;

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT,">$output";

my $code=<<___;
.text
___

################################################################################
# void gcm_init_rv64i_zvkg(u128 Htable[16], const u64 H[2]);
# void gcm_init_rv64i_zvkg__zbb_or_zbkb(u128 Htable[16], const u64 H[2]);
# void gcm_init_rv64i_zvkg__zvkb(u128 Htable[16], const u64 H[2]);
#
# input: H: 128-bit H - secret parameter E(K, 0^128)
# output: Htable: Copy of secret parameter (in normalized byte order)
#
# All callers of this function revert the byte-order unconditionally
# on little-endian machines. So we need to revert the byte-order back.
{
my ($Htable,$H,$VAL0,$VAL1,$TMP0) = ("a0","a1","a2","a3","t0");

$code .= <<___;
.p2align 3
.globl gcm_init_rv64i_zvkg
.type gcm_init_rv64i_zvkg,\@function
gcm_init_rv64i_zvkg:
    # First word
    ld      $VAL0, 0($H)
    ld      $VAL1, 8($H)
    @{[sd_rev8_rv64i $VAL0, $Htable, 0, $TMP0]}
    @{[sd_rev8_rv64i $VAL1, $Htable, 8, $TMP0]}
    ret
.size gcm_init_rv64i_zvkg,.-gcm_init_rv64i_zvkg
___
}

{
my ($Htable,$H,$TMP0,$TMP1) = ("a0","a1","t0","t1");

$code .= <<___;
.p2align 3
.globl gcm_init_rv64i_zvkg__zbb_or_zbkb
.type gcm_init_rv64i_zvkg__zbb_or_zbkb,\@function
gcm_init_rv64i_zvkg__zbb_or_zbkb:
    ld      $TMP0,0($H)
    ld      $TMP1,8($H)
    @{[rev8 $TMP0, $TMP0]}           #rev8    $TMP0, $TMP0
    @{[rev8 $TMP1, $TMP1]}           #rev8    $TMP1, $TMP1
    sd      $TMP0,0($Htable)
    sd      $TMP1,8($Htable)
    ret
.size gcm_init_rv64i_zvkg__zbb_or_zbkb,.-gcm_init_rv64i_zvkg__zbb_or_zbkb
___
}

{
my ($Htable,$H,$V0) = ("a0","a1","v0");

$code .= <<___;
.p2align 3
.globl gcm_init_rv64i_zvkg__zvkb
.type gcm_init_rv64i_zvkg__zvkb,\@function
gcm_init_rv64i_zvkg__zvkb:
    # All callers of this function revert the byte-order unconditionally
    # on little-endian machines. So we need to revert the byte-order back.
    @{[vsetivli__x0_2_e64_m1_ta_ma]} # vsetivli x0, 2, e64, m1, ta, ma
    @{[vle64_v $V0, $H]}             # vle64.v v0, (a1)
    @{[vrev8_v $V0, $V0]}            # vrev8.v v0, v0
    @{[vse64_v $V0, $Htable]}        # vse64.v v0, (a0)
    ret
.size gcm_init_rv64i_zvkg__zvkb,.-gcm_init_rv64i_zvkg__zvkb
___
}

################################################################################
# void gcm_gmult_rv64i_zvkg(u64 Xi[2], const u128 Htable[16]);
#
# input: Xi: current hash value
#        Htable: copy of H
# output: Xi: next hash value Xi
{
my ($Xi,$Htable) = ("a0","a1");
my ($VD,$VS2) = ("v1","v2");

$code .= <<___;
.p2align 3
.globl gcm_gmult_rv64i_zvkg
.type gcm_gmult_rv64i_zvkg,\@function
gcm_gmult_rv64i_zvkg:
    @{[vsetivli__x0_4_e32_m1_ta_ma]}
    @{[vle32_v $VS2, $Htable]}
    @{[vle32_v $VD, $Xi]}
    @{[vgmult_vv $VD, $VS2]}
    @{[vse32_v $VD, $Xi]}
    ret
.size gcm_gmult_rv64i_zvkg,.-gcm_gmult_rv64i_zvkg
___
}

################################################################################
# void gcm_ghash_rv64i_zvkg(u64 Xi[2], const u128 Htable[16],
#                           const u8 *inp, size_t len);
#
# input: Xi: current hash value
#        Htable: copy of H
#        inp: pointer to input data
#        len: length of input data in bytes (mutiple of block size)
# output: Xi: Xi+1 (next hash value Xi)
{
my ($Xi,$Htable,$inp,$len) = ("a0","a1","a2","a3");
my ($vXi,$vH,$vinp,$Vzero) = ("v1","v2","v3","v4");

$code .= <<___;
.p2align 3
.globl gcm_ghash_rv64i_zvkg
.type gcm_ghash_rv64i_zvkg,\@function
gcm_ghash_rv64i_zvkg:
    @{[vsetivli__x0_4_e32_m1_ta_ma]}
    @{[vle32_v $vH, $Htable]}
    @{[vle32_v $vXi, $Xi]}

Lstep:
    @{[vle32_v $vinp, $inp]}
    add $inp, $inp, 16
    add $len, $len, -16
    @{[vghash_vv $vXi, $vinp, $vH]}
    bnez $len, Lstep

    @{[vse32_v $vXi, $Xi]}
    ret

.size gcm_ghash_rv64i_zvkg,.-gcm_ghash_rv64i_zvkg
___
}

print $code;

close STDOUT or die "error closing STDOUT: $!";
