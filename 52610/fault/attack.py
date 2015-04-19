import sys, subprocess

# The round constant matrix
# hr
RCon = [
    [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a],
    [0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39],
    [0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a],
    [0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8],
    [0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef],
    [0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc],
    [0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b],
    [0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3],
    [0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94],
    [0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20],
    [0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35],
    [0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f],
    [0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04],
    [0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63],
    [0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd],
    [0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d]
]

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

def InvSubBytes(x) :
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
  ciphertext = int( target_out.readline().strip(), 16 )

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

    fault = r + ',' + f + ',' + p +',' + 'i' + ',' + 'j'
    return fault

################################################################################
## First Step Of The Attack                                                   ##
################################################################################

def eq(xi, xp1, ki) :
    return add(RSubBytes(add(xi, k1)), RSubBytes(add(xpi, ki)))

# Solve first set of equations
# k1, k8, k11, k14
def equation1(x, xp) :
    # Get ciphertext and faulty ciphertext byte values
    x1   = getByte(x, 1)
    xp1  = getByte(xp, 1)
    x8   = getByte(x, 8)
    xp8  = getByte(xp, 8)
    x11  = getByte(x, 11)
    xp11 = getByte(xp, 11)
    x14  = getByte(x, 14)
    xp14 = getByte(xp, 14)

    k1  = []
    k8  = []
    k11 = []
    k14 = []

    k1append  = k1.append
    k8append  = k8.append
    k11append = k11.append
    k14append = k14.append

    for d1 in range(1:256) :
        k1  = []
        k8  = []
        k11 = []
        k14 = []

        # k1
        for k in range(256) :
            if mul(2, d1) == eq(x1, xp1, k) :
                k1append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k1 == [] :
            continue

        # k14
        for k in range(256) :
            if d1 == eq(x14, xp14, k) :
                k14append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k14 == [] :
            continue

        # k11
        for k in range(256) :
            if d1 == eq(x11, xp11, k) :
                k11append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k11 == [] :
            continue

        # k8
        for k in range(256) :
            if mul(3, d1) == eq(x8, xp8, k) :
                k8append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d1 can be discarded
        if k8 == [] :
            continue

    # possible key values
    keyBytes = []
    keyBytesAppend = keyBytes.append
    for a1 in k1 :
        for a8 in k8 :
            for a11 in k11 :
                for a14 in k14 :
                    keyBytesAppend((a1, a8, a11, a14))

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

    k2  = []
    k5  = []
    k12 = []
    k15 = []

    k2append  = k2.append
    k5append  = k5.append
    k12append = k12.append
    k15append = k15.append

    for d2 in range(1:256) :
        k2  = []
        k5  = []
        k12 = []
        k15 = []

        # k5
        for k in range(256) :
            if d2 == eq(x5, xp5, k) :
                k5append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k5 == [] :
            continue

        # k2
        for k in range(256) :
            if d2 == eq(x2, xp2, k) :
                k2append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k2 == [] :
            continue

        # k15
        for k in range(256) :
            if mul(3, d2) == eq(x15, xp15, k) :
                k15append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k15 == [] :
            continue

        # k12
        for k in range(256) :
            if mul(2, d2) == eq(x12, xp12, k) :
                k12append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d2 can be discarded
        if k12 == [] :
            continue

    # possible key values
    keyBytes = []
    keyBytesAppend = keyBytes.append
    for a2 in k2 :
        for a5 in k5 :
            for a12 in k12 :
                for a15 in k15 :
                    keyBytesAppend((a2, a5, a12, a15))

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

    k3  = []
    k6  = []
    k9 = []
    k16 = []

    k3append  = k3.append
    k6append  = k6.append
    k9append  = k9.append
    k16append = k16.append

    for d3 in range(1:256) :
        k3  = []
        k6  = []
        k9  = []
        k16 = []

        # k9
        for k in range(256) :
            if d3 == eq(x9, xp9, k) :
                k9append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k9 == [] :
            continue

        # k6
        for k in range(256) :
            if mul(3, d3) == eq(x6, xp6, k) :
                k6append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k6 == [] :
            continue

        # k3
        for k in range(256) :
            if mul(2, d3) == eq(x3, xp3, k) :
                k3append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k3 == [] :
            continue

        # k16
        for k in range(256) :
            if d3 == eq(x16, xp16, k) :
                k16append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d3 can be discarded
        if k16 == [] :
            continue

    # possible key values
    keyBytes = []
    keyBytesAppend = keyBytes.append
    for a3 in k3 :
        for a6 in k6 :
            for a9 in k9 :
                for a16 in k16 :
                    keyBytesAppend((a3, a6, a9, a16))

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

    k4  = []
    k7  = []
    k10 = []
    k13 = []

    k4append  = k4.append
    k7append  = k7.append
    k10append = k10.append
    k13append = k13.append

    for d4 in range(1:256) :
        k4  = []
        k7  = []
        k10 = []
        k13 = []

        # k13
        for k in range(256) :
            if mul(3, d4) == eq(x13, xp13, k) :
                k13append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k13 == [] :
            continue

        # k10
        for k in range(256) :
            if mul(2, d4) == eq(x10, xp10, k) :
                k10append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k10 == [] :
            continue

        # k7
        for k in range(256) :
            if d4 == eq(x7, xp7, k) :
                k7append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k4 == [] :
            continue

        # k4
        for k in range(256) :
            if d4 == eq(x4, xp4, k) :
                k4append(k)
        # If the equation cannot be satisfied there is an impossible differential
        # the value of d4 can be discarded
        if k4 == [] :
            continue

    # possible key values
    keyBytes = []
    keyBytesAppend = keyBytes.append
    for a4 in k4 :
        for a7 in k7 :
            for a10 in k10 :
                for a13 in k13 :
                    keyBytesAppend((a4, a7, a10, a13))

    return keyBytes

def step1(x, xp) :
    # k1, k8, k11, k14
    set1 = equation1(x, xp)
    # k2, k5, k12, k15
    set2 = equation2(x, xp)
    # k3, k6, k9, k16
    set3 = equation3(x, xp)
    # k4, k7, k10, k13
    set4 = equation4(x, xp)

    keys = []
    keysAppend = keys.append

    for s1 in set1 :
        (k1, k8, k11, k14) = s1
        for s2 in set2 :
            (k2, k5, k12, k15) = s2
            for s3 in set3 :
                (k3, k6, k9, k16) = s3
                for s4 in set4 :
                    (k4, k7, k10, k13) = s4
                    keysAppend((k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16))

    return keys

################################################################################

def attack() :
    print SubBytes(1)

if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  # Execute a function representing the attacker.
  attack()
