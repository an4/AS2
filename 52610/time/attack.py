import sys, subprocess
import random
from Crypto.Util import number

# Number of ciphertexts to be generated
count = 10000

# Montgomery
# word size
w = 64
# Base
b = 1 << 64

# Compute Montgomery rho
def M_rho () :
    global rho
    rho = 1
    while rho <= N :
        rho *= b

# Compute Montgomery omega
def M_omega () :
    global omega
    omega = (-number.inverse(N, rho)) % rho

# Compute Montgomery rho squared
def M_rho_sq () :
    global rho_sq
    rho_sq = (rho**2) % N

def M_param() :
    M_rho()
    M_omega()
    M_rho_sq()

# Montgomery Multiplication from: "Analyzing And Comparing Montgomery Multiplication
# Algorithms" (page 2)
def MonPro(a, b) :
    t = a * b
    u = (t + (t * omega % rho) * N) / rho
    # Check if reduction is needed
    if u >= N :
        return (u - N, True)
    else :
        return (u, False)

# Square and multiply
# Square and multiplly for the first bit takes 1.5 steps (square, multiply, square)
# After performing square and multiply for the current bit we need an additional
# square operation to determine if there has been a reduction or not.
def SAM_init(ciphertext) :
    # First bit is always set so we do not need to check its value.
    temp = 1
    # Use Montgomery form
    temp, _ = MonPro(temp, rho_sq)
    c, _ = MonPro(ciphertext, rho_sq)

    # Square and multiply for current bit (first bit set)
    temp, _ = MonPro(temp, temp)
    temp, _ = MonPro(temp, c)

    # Square operation that determines if the reduction was performed
    temp, _ = MonPro(temp, temp)

    # Return temporary value of result, temp, and the value of the ciphertext
    # in Montgomery form c.
    return (temp, c)

# Square and multiply for all bits except the first (always 1) and last one.
# The function performs the multiply step for the current bit, and the squaring
# for the next bit to determine if there was a reduction.
def SAM(cipher, temp, ith) :
    # cipher is already in Montgomery form
    if ith == 1 :
        temp, _ = MonPro(temp, cipher)
    return MonPro(temp, temp)

# Read Public Key
def readParams( file ) :
    global N, e

    # Read modulus N
    temp = file.readline()
    # Remove new line character
    temp = temp[:-1]
    # Convert to decimal
    N = int(temp, 16)

    # Read public exponent e
    temp = file.readline()
    # Remove new line character
    temp = temp[:-1]
    # Convert to decimal
    e = int(temp, 16)

    file.close()

# Generate ciphertexts for timing.
def generate(x) :
    ciphertext = []
    for i in range(x) :
        # ciphertext in [0,N)
        ciphertext.append(random.randint(0, N-1))
    return ciphertext

# interact with *.D
def interact( ciphertext ) :
    # Send ciphertext to attack target.
    target_in.write( "%s\n" % ( ciphertext ) ) ; target_in.flush()

    # Receive ( time, message ) from attack target.
    # time = an execution time measured in clock cycles
    # m = plaintext, represented as a hexadecimal integer string
    time      = int( target_out.readline().strip() )
    message   = int( target_out.readline().strip(), 16 )

    return ( time, message )

def initialize () :
    for i in range(count) :
        T, M = SAM_init(ciphertext[i])
        ciphertext_T.append(T)
        ciphertext_M.append(M)

def getNext() :
    # The bit is one, reduction
    BSetRed = [0, 0]
    # The bit is one, no reduction
    BSetNoRed = [0, 0]
    # The bit is zero, reduction
    BNotSetRed = [0, 0]
    # The bit is zero, no reduction
    BNotSetNoRed = [0, 0]

    global ciphertext_T

    ciphertext_T_t = {}
    ciphertext_T_t[0] = []
    ciphertext_T_t[1] = []

    for i in range(count) :
        # Get time
        ( time, message ) = interact( ciphertext[i] )
        # Check when bit is set
        (T, B) = SAM(ciphertext[i], ciphertext_T[i], 1)
        ciphertext_T_t[1].append(T)
        if B :
            BSetRed[0] += 1
            BSetRed[1] += time
        else:
            BSetNoRed[0] += 1
            BSetNoRed[1] += time
        # Check when bit is not set
        T, B = SAM(ciphertext[i], ciphertext_T[i], 0)
        ciphertext_T_t[0].append(T)
        if B :
            BNotSetRed[0] += 1
            BNotSetRed[1] += time
        else:
            BNotSetNoRed[0] += 1
            BNotSetNoRed[1] += time

    M1 = float(BSetRed[1]/BSetRed[0])
    M2 = float(BSetNoRed[1]/BSetNoRed[0])
    M3 = float(BNotSetRed[1]/BNotSetRed[0])
    M4 = float(BNotSetNoRed[1]/BNotSetNoRed[0])

    if (abs(M1-M2) > abs(M3-M4)) :
        bit = 1
    else:
        bit = 0

    ciphertext_T = ciphertext_T_t[bit]
    return bit

def attack() :
    global ciphertext, ciphertext_M, ciphertext_T
    # List of initial ciphertexts
    ciphertext = []
    # List of ciphertexts in Montgomery form
    ciphertext_M = []
    # Temporary value of final result
    ciphertext_T = []

    # Generate random ciphertexts
    ciphertext = generate(count)

    # Compute Montgomery parameters
    M_param()

    # First bit is 1, set key to 1
    d = 1

    initialize()

    print getNext()



if ( __name__ == "__main__" ) :
    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE,
                             stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    # Read public parameters
    file = open(sys.argv[2], 'r')
    readParams(file)

    # Execute a function representing the attacker.
    attack()
