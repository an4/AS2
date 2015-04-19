import sys, subprocess
import random
import multiprocessing
from Crypto.Cipher import AES

BLOCK_SIZE = 128
kcount = 0

# Rijndael S-box
sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]

# Rijndael Inverted S-box
rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
        0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
        0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
        0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
        0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
        0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
        0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
        0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
        0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
        0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
        0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
        0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
        0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
        0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e ,0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
        0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
        0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
        0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
        0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
        0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
        0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
        0x21, 0x0c, 0x7d]

# Paper starts from 1 ??
def getByte(ByteString, index) :
    byte = ByteString[(index-1)*2 : index*2]
    return int(byte, 16)

def SubBytes(x) :
    return sbox[x]

def RSubBytes(x) :
    x = x%256
    return rsbox[x]

# Addition, Substraction and Multiplication in F8
# Taken from: http://www.cs.bris.ac.uk/home/page/teaching/material/security/slide/symmetric-01_s.pdf

# Addition in F8
def add(a, b) :
    return a^b

# Substraction in F8
def sub(a, b) :
    return a^b

# Multiplication in F8
def mulx(a) :
    if a & 0x80 == 0x80 :
        return 0x80 ^ (a << 1)
    else :
        return (a << 1)

def mul(a, b) :
    t = 0;
    for i in range(7, -1, -1) :
        t = mulx(t)
        if ((b >> i) & i) :
            t = t ^ a
    return t

def interact( fault, message ) :
  # Send fault and message to attack target.
  target_in.write( "%s\n" % ( fault ) ) ; target_in.flush()
  target_in.write( "%s\n" % ( message.zfill(32) ) ) ; target_in.flush()

  # Receive ciphertext from attack target.
  ciphertext = target_out.readline().strip()
  return ciphertext

# Return the fault specification as a 5-element tuple
def getFault() :
    # round
    r = '8'
    # function
    f = '1'
    # before or after execution
    p = '0'
    # row and column of the state matrix
    i = '0'
    j = '0'

    fault = r + ',' + f + ',' + p + ',' + i + ',' + j
    return fault

################################################################################
## First Step Of The Attack                                                   ##
################################################################################

def eq(xi, xpi, ki) :
    return add(RSubBytes(add(xi, ki)), RSubBytes(add(xpi, ki)))

# Solve first set of equations
# k1, k8, k11, k14
def equation1(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x1   = getByte(x,  1)
    xp1  = getByte(xp, 1)
    x8   = getByte(x,  8)
    xp8  = getByte(xp, 8)
    x11  = getByte(x,  11)
    xp11 = getByte(xp, 11)
    x14  = getByte(x,  14)
    xp14 = getByte(xp, 14)

    # possible key values
    keyBytes = []

    for d1 in range(1, 256) :
        k1  = []
        k8  = []
        k11 = []
        k14 = []

        # k1
        for k in range(256) :
            if mul(2, d1) == eq(x1, xp1, k) :
                k1 = [k] + k1
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k1 == [] :
            continue

        # k14
        for k in range(256) :
            if d1 == eq(x14, xp14, k) :
                k14 = [k] + k14
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k14 == [] :
            continue

        # k11
        for k in range(256) :
            if d1 == eq(x11, xp11, k) :
                k11 = [k] + k11
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k11 == [] :
            continue

        # k8
        for k in range(256) :
            if mul(3, d1) == eq(x8, xp8, k) :
                k8 = [k] + k8
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k8 == [] :
            continue

        for a1 in k1 :
            for a8 in k8 :
                for a11 in k11 :
                    for a14 in k14 :
                        keyBytes = [(a1, a8, a11, a14)] + keyBytes

    return keyBytes

# Solve second set of equations
# k2, k5, k12, k15
def equation2(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x2   = getByte(x,  2)
    xp2  = getByte(xp, 2)
    x5   = getByte(x,  5)
    xp5  = getByte(xp, 5)
    x12  = getByte(x,  12)
    xp12 = getByte(xp, 12)
    x15  = getByte(x,  15)
    xp15 = getByte(xp, 15)

    # possible key values
    keyBytes = []

    for d2 in range(1, 256) :
        k2  = []
        k5  = []
        k12 = []
        k15 = []

        # k5
        for k in range(256) :
            if d2 == eq(x5, xp5, k) :
                k5 = [k] + k5
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k5 == [] :
            continue

        # k2
        for k in range(256) :
            if d2 == eq(x2, xp2, k) :
                k2 = [k] + k2
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k2 == [] :
            continue

        # k15
        for k in range(256) :
            if mul(3, d2) == eq(x15, xp15, k) :
                k15 = [k] + k15
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k15 == [] :
            continue

        # k12
        for k in range(256) :
            if mul(2, d2) == eq(x12, xp12, k) :
                k12 = [k] + k12
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k12 == [] :
            continue

        for a2 in k2 :
            for a5 in k5 :
                for a12 in k12 :
                    for a15 in k15 :
                        keyBytes = [(a2, a5, a12, a15)] + keyBytes

    return keyBytes

# Solve third set of equations
# k3, k6, k9, k16
def equation3(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x3   = getByte(x,  3)
    xp3  = getByte(xp, 3)
    x6   = getByte(x,  6)
    xp6  = getByte(xp, 6)
    x9   = getByte(x,  9)
    xp9  = getByte(xp, 9)
    x16  = getByte(x,  16)
    xp16 = getByte(xp, 16)

    # possible key values
    keyBytes = []

    for d3 in range(1, 256) :
        k3  = []
        k6  = []
        k9  = []
        k16 = []

        # k9
        for k in range(256) :
            if d3 == eq(x9, xp9, k) :
                k9 = [k] + k9
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k9 == [] :
            continue

        # k6
        for k in range(256) :
            if mul(3, d3) == eq(x6, xp6, k) :
                k6 = [k] + k6
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k6 == [] :
            continue

        # k3
        for k in range(256) :
            if mul(2, d3) == eq(x3, xp3, k) :
                k3 = [k] + k3
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k3 == [] :
            continue

        # k16
        for k in range(256) :
            if d3 == eq(x16, xp16, k) :
                k16 = [k] + k16
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k16 == [] :
            continue

        for a3 in k3 :
            for a6 in k6 :
                for a9 in k9 :
                    for a16 in k16 :
                        keyBytes = [(a3, a6, a9, a16)] + keyBytes

    return keyBytes

# Solve forth set of equations
# k4, k7, k10, k13
def equation4(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x4   = getByte(x,  4)
    xp4  = getByte(xp, 4)
    x7   = getByte(x,  7)
    xp7  = getByte(xp, 7)
    x10  = getByte(x,  10)
    xp10 = getByte(xp, 10)
    x13  = getByte(x,  13)
    xp13 = getByte(xp, 13)

    # possible key values
    keyBytes = []
    addKeyBytes = keyBytes.append

    for d4 in xrange(1, 256) :
        k4  = []
        k7  = []
        k10 = []
        k13 = []

        add4 = k4.append
        add7 = k7.append
        add10 = k10.append
        add13 = k13.append

        # k13
        for k in xrange(256) :
            if mul(3, d4) == eq(x13, xp13, k) :
                add13(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k13 == [] :
            continue

        # k10
        for k in xrange(256) :
            if mul(2, d4) == eq(x10, xp10, k) :
                add10(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k10 == [] :
            continue

        # k7
        for k in xrange(256) :
            if d4 == eq(x7, xp7, k) :
                add7(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k7 == [] :
            continue

        # k4
        for k in xrange(256) :
            if d4 == eq(x4, xp4, k) :
                add4(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k4 == [] :
            continue

        for a4 in k4 :
            for a7 in k7 :
                for a10 in k10 :
                    for a13 in k13 :
                        addKeyBytes((a4, a7, a10, a13))

    return keyBytes

################################################################################

################################################################################
## Second Step Of The Attack                                                  ##
################################################################################

def getByteList(x) :
    x1   = getByte(x,  1)
    x2   = getByte(x,  2)
    x3   = getByte(x,  3)
    x4   = getByte(x,  4)
    x5   = getByte(x,  5)
    x6   = getByte(x,  6)
    x7   = getByte(x,  7)
    x8   = getByte(x,  8)
    x9   = getByte(x,  9)
    x10  = getByte(x,  10)
    x11  = getByte(x,  11)
    x12  = getByte(x,  12)
    x13  = getByte(x,  13)
    x14  = getByte(x,  14)
    x15  = getByte(x,  15)
    x16  = getByte(x,  16)

    # starts from 1
    return [0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16]

# RSubBytes(add(a, b))
def rsbxk(a, b) :
    return RSubBytes( add(a, b) )

# SubBytes(add(a, b))
def sbxk(a, b) :
    return SubBytes( add(a, b) )

def addsb(a, b, c) :
    return add(a, sbxk(b, c))

def addrsb(a, b, c) :
    return add(a, rsbxk(b, c))

def muladd(a, b, c) :
    return mul(a, add(b, c))

def addadd(a, b, c, d) :
    return add(add(a, b), add(c, d))

def equ1(x, xp, k, h10) :
    l1 = muladd(14, rsbxk(x[1],   k[1]),  add( addsb(k[1], k[14], k[10]), h10))
    l2 = muladd(11, rsbxk(x[14],  k[14]), addsb(k[2], k[15], k[11]))
    l3 = muladd(13, rsbxk(x[11],  k[11]), addsb(k[3], k[16], k[12]))
    l4 = muladd( 9, rsbxk(x[8],   k[8]),  addsb(k[4], k[13], k[9]))
    l5 = muladd(14, rsbxk(xp[1],  k[1]),  add( addsb(k[1], k[14], k[10]), h10))
    l6 = muladd(11, rsbxk(xp[14], k[14]), addsb(k[2], k[15], k[11]))
    l7 = muladd(13, rsbxk(xp[11], k[11]), addsb(k[3], k[16], k[12]))
    l8 = muladd( 9, rsbxk(xp[8],  k[8]),  addsb(k[4], k[13], k[9]))
    return add (RSubBytes(addadd(l1, l2, l3, l4)), RSubBytes(addadd(l5, l6, l7, l8)))

def equ2(x, xp, k) :
    l1 = muladd( 9, rsbxk(x[13],  k[13]), add(k[13], k[9]))
    l2 = muladd(14, rsbxk(x[10],  k[10]), add(k[10], k[14]))
    l3 = muladd(11, rsbxk(x[7],   k[7]),  add(k[15], k[11]))
    l4 = muladd(13, rsbxk(x[4],   k[4]),  add(k[16], k[12]))
    l5 = muladd( 9, rsbxk(xp[13], k[13]), add(k[13], k[9]))
    l6 = muladd(14, rsbxk(xp[10], k[10]), add(k[10], k[14]))
    l7 = muladd(11, rsbxk(xp[7],  k[7]),  add(k[15], k[11]))
    l8 = muladd(13, rsbxk(xp[4],  k[4]),  add(k[16], k[12]))
    return add (RSubBytes(addadd(l1, l2, l3, l4)), RSubBytes(addadd(l5, l6, l7, l8)))

def equ3(x, xp, k) :
    l1 = muladd(13, rsbxk(x[9],   k[9]),  add(k[9],  k[5]))
    l2 = muladd( 9, rsbxk(x[6],   k[6]),  add(k[10], k[6]))
    l3 = muladd(14, rsbxk(x[3],   k[3]),  add(k[11], k[7]))
    l4 = muladd(11, rsbxk(x[16],  k[16]), add(k[12], k[8]))
    l5 = muladd(13, rsbxk(xp[9],  k[9]),  add(k[9],  k[5]))
    l6 = muladd( 9, rsbxk(xp[6],  k[6]),  add(k[10], k[6]))
    l7 = muladd(14, rsbxk(xp[3],  k[3]),  add(k[11], k[7]))
    l8 = muladd(11, rsbxk(xp[16], k[16]), add(k[12], k[8]))
    return add (RSubBytes(addadd(l1, l2, l3, l4)), RSubBytes(addadd(l5, l6, l7, l8)))

def equ4(x, xp, k) :
    l1 = muladd(11, rsbxk(x[5],   k[5]),  add(k[5],  k[1]))
    l2 = muladd(13, rsbxk(x[2],   k[2]),  add(k[6],  k[2]))
    l3 = muladd(9,  rsbxk(x[15],  k[15]), add(k[7],  k[3]))
    l4 = muladd(14, rsbxk(x[12],  k[12]), add(k[8],  k[4]))
    l5 = muladd(11, rsbxk(xp[5],  k[5]),  add(k[5],  k[1]))
    l6 = muladd(13, rsbxk(xp[2],  k[2]),  add(k[6],  k[2]))
    l7 = muladd(9,  rsbxk(xp[15], k[15]), add(k[7],  k[3]))
    l8 = muladd(14, rsbxk(xp[12], k[12]), add(k[8],  k[4]))
    return add (RSubBytes(addadd(l1, l2, l3, l4)), RSubBytes(addadd(l5, l6, l7, l8)))

def step2(abc) :
    (k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, x, xp) = abc
    k = (0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16)

    h10 = 0x36
    global kcount

    f1 = equ1(x, xp, k, h10)
    f2 = equ2(x, xp, k)
    f3 = equ3(x, xp, k)
    f4 = equ4(x, xp, k)

    if mul(2,f2) == f1 and f2 == f3 and mul(3, f3) == f4 :
        kcount += 1
        return k
    else :
        return 0

################################################################################

def getString(k) :
    (k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, x, xp) = k
    key = "%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X" % (k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16)
    return key

def test_key() :
    plaintext = str(hex(random.getrandbits(BLOCK_SIZE)))[2:-1]
    ciphertext = interact('', plaintext)

    key = getString()

    IV = 16 * '\x00'
    mode = AES.MODE_CBC
    encryptor = AES.new(key, mode, IV=IV)

    test_ciphertext = int(encryptor.encrypt(plaintext), 16)

    if test_ciphertext == ciphertext :
        return 1
        print "\n Key found:"
        print "%X" % key
    else :
        return 0

def attack(pool) :
    # Generate plaintext
    plaintext = str(hex(random.getrandbits(BLOCK_SIZE)))[2:-1]

    # Get fault
    fault = getFault()

    # Get faulty ciphertext
    xp = interact(fault, plaintext)
    # Get correct ciphertext
    x = interact('', plaintext)

    print "Step 1 :"
    # k1, k8, k11, k14
    print "Set 1 ..."
    set1 = equation1(x, xp)
    print "Keys: " + str(len(set1))
    # k2, k5, k12, k15
    print "Set 2 ..."
    set2 = equation2(x, xp)
    print "Keys: " + str(len(set2))
    # k3, k6, k9, k16
    print "Set 3 ..."
    set3 = equation3(x, xp)
    print "Keys: " + str(len(set3))
    # k4, k7, k10, k13
    print "Set 4 ..."
    set4 = equation4(x, xp)
    print "Keys: " + str(len(set4))

    inputs = []

    x  = getByteList(x)
    xp = getByteList(xp)

    total = len(set1) * len(set2) * len(set3) * len(set4)
    i = 0

    add = inputs.append

    print "Step 2 :"
    for a in xrange(len(set1)):
        (k1, k8, k11, k14) = set1[a]
        for b in xrange(len(set2)) :
            (k2, k5, k12, k15) = set2[b]
            for c in xrange(len(set3)) :
                (k3, k6, k9, k16) = set3[c]
                for d in xrange(len(set4)) :
                    (k4, k7, k10, k13) = set4[d]

                    add((k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, x, xp))

                    i+=1
                    sys.stdout.write("\rDoing thing %d/%d, keys found: %d" %(i,total, kcount))
                    sys.stdout.flush()

                keys = pool.map( step2, inputs )
                inputs = []
                for sk in xrange(len(keys)) :
                    if keys[sk] != 0 :
                        if test_key(keys[sk]) :
                            return 1


if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  pool = multiprocessing.Pool(multiprocessing.cpu_count())

  # Execute a function representing the attacker.
  while 1 :
      if attack(pool) == 1 :
          break
