import sys, subprocess

def interact( fault, message ) :
  # Send fault and message to attack target.
  target_in.write( "%s\n" % ( fault ) ) ; target_in.flush()
  target_in.write( "%s\n" % ( message ) ) ; target_in.flush()

  # Receive ciphertext from attack target.
  ciphertext = int( target_out.readline().strip(), 16 )

  return ciphertext

def attack() :


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
