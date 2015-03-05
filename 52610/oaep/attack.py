import sys, subprocess
import math

# Error codes
SUCCESS = 0
ERROR1  = 1
ERROR2  = 2
# Message out of range
M_RANGE = 3
# Ciphertext out of range
C_RANGE = 4
# Message too long mLen > k - 2hLen - 2
M_LEN   = 5
# Ciphertext does not match the length of N
C_LEN   = 6
# CIphertext does not match the length of the hash function output
CH_LEN  = 7

# Read Public Key and Ciphertext from User.param and calculate k and B
def readParams( file ) :
    global N, k, B, e, c, count

    # Read modulus N
    temp = file.readline()
    # Remove new line character
    temp = temp[:-1]
    # Convert to decimal
    N = int(temp, 16)

    # Calculate k, the byte length of N
    # k = ceil[log 256 N]
    # k = (number of octet in N) / 2
    k = len(temp)/2

    # Calculate B = 2^(8*(k-1))
    B =  pow(2, 8*(k-1))

    # Read public exponent e
    temp = file.readline()
    # Remove new line character
    temp = temp[:-1]
    # Convert to decimal
    e = int(temp, 16)

    # Read ciphertext c
    temp = file.readline()
    # Remove new line character
    temp = temp[:-1]
    # Convert to decimal
    c = int(temp, 16)

    count = 0

    file.close()

def interact( ciphertext ) :
    # count interactions
    global count
    count += 1

    # Send ciphertext to attack target. Ciphertext length must me 256.
    target_in.write( "%s\n" % ("%X" % ciphertext ).zfill(256) ) ; target_in.flush()

    # Receive ( t, r ) from attack target.
    return int( target_out.readline().strip() )

def oracle(f) :
    result = pow(f, e, N)
    result = result * c
    result = result % N
    return interact(result)

def Step1() :
    f1 = 2

    # Try f1 with oracle
    errCode = oracle(f1)

    while errCode == ERROR2 :
        f1 = f1 * 2
        errCode = oracle(f1)

    # Step 1.3b
    # Check if errCode indicates "<B", if not something went wrong.
    if errCode != ERROR1 :
        raise Exception("Something went wrong!")

    return f1

def Step2(f1) :
    temp = f1 / 2
    f2 = math.floor((N+B)/B) * temp

    # Try f2 with oracle
    errCode = oracle(f2)

    while errCode == ERROR1 :
        f2 = f2 + temp
        errCode = oracle(f2)

    # check if the oracle indicates "<B", if not something went wrong
    if errCode != ERROR2 :
        raise Exception("Something went wrong!")

    return f2

def Step3(f2) :
    # 3.1
    mmin = math.ceil(N/f2)
    mmax = math.floor((N+B)/f2)

    while mmin != mmax :
        # 3.2
        ftmp = math.floor((2*B) / (mmax-mmin))

        # 3.3
        i = math.floor((ftmp*mmin)/N)
        in = i * N

        # 3.4
        f3 = math.ceil(in/mmin)
        #Try with oracle
        errCode = oracle(f3)

        if errCode == ERROR1 :
            # 3.5a
            mmin = math.ceil((in + B) / f3)
        elif errCode == ERROR2 :
            # 3.5b
            mmax = math.floor((in + B) / f3)
        else:
            raise Exception("Something went wrong!")

    return ("%X" % mmin).zfill(256)

def attack() :
    f1 = Step1()

    f2 = Step2(f1)

    m = Step3(f2)

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
