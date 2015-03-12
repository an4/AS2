import sys, subprocess

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

def interact( ciphertext ) :
    # Send ciphertext to attack target.
    target_in.write( "%s\n" % ( ciphertext ) ) ; target_in.flush()

    # Receive ( time, message ) from attack target.
    # time = an execution time measured in clock cycles
    # m = plaintext, represented as a hexadecimal integer string

    time      = int( target_out.readline().strip() )
    message   = int( target_out.readline().strip(), 16 )

    return ( time, message )

def attack() :
    # interact with the attack target.
    ( time, message ) = interact( "ciphertext" )

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
