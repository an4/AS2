import sys, subprocess
import random, math
from Crypto.Util import number
import numpy as np

# Public Key
N = 0
e = 0

# Private Key
d = 1

# Montgomery parameters
# word size
w = 64
# Base
b = (1 << w)
#
rho = 0
#
omega = 0
#
rho_sq = 0

# Ciphertext to be generated
size = 5000

# Confidence level, when is the bit accepted?
level = 2.0

interactions = 0

# Test private key
def test (d) :
    m = 0x123456
    c = pow(m, e, N)
    m_r = pow(c, d, N)
    return m == m_r

# interact with {user}.D
def interact( ciphertext ) :
    global interactions
    interactions += 1

    # Send ciphertext to attack target.
    target_in.write( "%X\n" % ( ciphertext ) ) ; target_in.flush()

    # Receive ( time, message ) from attack target.
    # time = an execution time measured in clock cycles
    # m = plaintext, represented as a hexadecimal integer string
    time      = int( target_out.readline().strip() )
    message   = int( target_out.readline().strip(), 16 )

    return time

# Read Public Key from {user}.param
def readPK( name ) :
    file = open(name, 'r')
    global N, e
    N = int(file.readline(), 16)
    e = int(file.readline(), 16)
    file.close()

# Compute Montgomery rho
def getRho() :
    temp = 1
    while temp <= N :
        temp *= b
    return temp

# Compute Montgomery omega
def getOmega() :
    return (-number.inverse(N, rho)) % rho

# Compute Montgomery rho squared
def getRhoSq() :
    return pow(rho, 2, N)

# Get all Montgomery parameters
def montParam() :
    global rho, omega, rho_sq
    rho = getRho()
    omega = getOmega()
    rho_sq = getRhoSq()

# Montgomery Multiplication from: "Analyzing And Comparing Montgomery Multiplication
# Algorithms" (page 2)
def MonPro(a, b) :
    t = a * b
    u = (t + (t * omega % rho) * N) / rho
    Red = False
    # Check if reduction is needed
    if u >= N :
        u = u - N
        Red = True
    return (u, Red)

def generate(x) :
    global cipher
    for i in range(x) :
        # ciphertext in [0,N)
        cipher.append(random.randint(0, N-1))

# Square and multiply
# Square and multiplly for the first bit takes 1.5 steps (square, multiply, square)
# After performing square and multiply for the current bit we need an additional
# square operation to determine if there has been a reduction or not.
def SAM_init(ciphertext) :
    # Use Montgomery form
    temp, _ = MonPro(1, rho_sq)
    mform, _ = MonPro(ciphertext, rho_sq)

    # Square and multiply for current bit (first bit always set)
    temp, _ = MonPro(temp, temp)
    temp, _ = MonPro(temp, mform)

    # Square operation that determines if the reduction was performed
    temp, _ = MonPro(temp, temp)

    # Return temporary value of result, temp, and the value of the ciphertext
    # in Montgomery form c.
    return (temp, mform)

# Generate ciphertexts and apply square and multiply 1.5 steps
# and get the time
def initialize() :
    global cipher, cipher_temp, cipher_mform, cipher_time
    # Ciphertexts
    cipher = []
    # Ciphertexts in Montgomery form
    cipher_mform = []
    # Temporary value between ciphertext and plaintext
    cipher_temp = []
    # Time for each ciphertext
    cipher_time = []

    print "Generate ciphertexts."
    generate(size)

    print "Working ..."
    for i in range(size) :
        time = interact(cipher[i])
        cipher_time.append(time)

        temp, mform = SAM_init(cipher[i])
        cipher_temp.append(temp)
        cipher_mform.append(mform)

# Square and multiply for all bits except the first (always 1) and last one.
# The function performs the multiply step for the current bit, and the squaring
# for the next bit to determine if there was a reduction.
def SAM(mform, temp, bit) :
    if bit == 1 :
        temp, _ = MonPro(temp, mform)
    temp, Red = MonPro(temp, temp)
    return (temp, Red)

def getNext() :
    global cipher_temp, size, d, cipher_mform

    while True :
        # The bit is one, reduction
        BSetRed = []
        # The bit is one, no reduction
        BSetNoRed = []
        # The bit is zero, reduction
        BNotSetRed = []
        # The bit is zero, no reduction
        BNotSetNoRed = []

        ciphertext_T_t = {}
        ciphertext_T_t[0] = []
        ciphertext_T_t[1] = []

        for i in range(size) :
            # Check when bit is set
            temp, Red = SAM(cipher_mform[i], cipher_temp[i], 1)
            ciphertext_T_t[1].append(temp)
            if Red :
                BSetRed.append(cipher_time[i])
            else :
                BSetNoRed.append(cipher_time[i])
            # Check when bit is not set
            temp, Red = SAM(cipher_mform[i], cipher_temp[i], 0)
            ciphertext_T_t[0].append(temp)
            if Red :
                BNotSetRed.append(cipher_time[i])
            else :
                BNotSetNoRed.append(cipher_time[i])

        M1 = np.mean(BSetRed)
        M2 = np.mean(BSetNoRed)
        M3 = np.mean(BNotSetRed)
        M4 = np.mean(BNotSetNoRed)

        diff_0 = abs(M3-M4)
        diff_1 = abs(M1-M2)
        diff = abs(diff_0 - diff_1)

        if ( diff_1 > diff_0) and diff > level :
            cipher_temp = ciphertext_T_t[1]
            sys.stdout.write('1'); sys.stdout.flush();
            return 1
        elif ( diff_1 < diff_0) and diff > level :
            cipher_temp = ciphertext_T_t[0]
            sys.stdout.write('0'); sys.stdout.flush();
            return 0
        else :
            print "\nCan't tell. Restart."
            # Increase sample size
            size += 1000
            # Generate ciphertexts
            initialize()
            # Reset private key
            d = 1
            sys.stdout.write('1'); sys.stdout.flush();

def attack() :
    global cipher, cipher_mform, cipher_temp, cipher_time, d

    if test(d) :
        print "Found key: " + str(bin(d))
        return

    # Last bit can't be guessed, try the two possible values
    d0 = (d << 1)
    if test(d0) :
        print "Found key: " + str(bin(d0))
        d = d2
        return
    d1 = (d << 1) | 1
    if test(d1) :
        print "Found key: " + str(bin(d1))
        d = d1
        return

    initialize()

    print "Start guessing ..."
    sys.stdout.write('1'); sys.stdout.flush();

    # Loop until the key is found
    while True :
        bit = getNext()
        d = (d << 1) | bit

        # Last bit can't be guessed, try the two possible values
        d0 = (d << 1)
        if test(d0) :
            print '0'
            print "Found key: " + str(bin(d0))
            d = d0
            break
        d1 = (d << 1) | 1
        if test(d1) :
            print '1'
            print "Found key: " + str(bin(d1))
            d = d1
            break

        if d >= N :
            print "\nSomething went wrong."
            # Increase sample size
            size += 1000
            # Generate ciphertexts
            initialize()
            # Reset private key
            d = 1
            sys.stdout.write('1'); sys.stdout.flush();

if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    # Read public parameters
    readPK(sys.argv[2])
    # Compute Montgomery parameters: rho, omeha and rho squared
    montParam()
    #
    attack()
    #
    print "Key in hex: " +str(hex(d))
    #
    print "Number of interactions with the attack target: " + str(interactions)
