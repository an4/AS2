import sys, subprocess

def interact( G ) :
  # Send      G      to   attack target.
  target_in.write( "%s\n" % ( G ).zfill(256) ) ; target_in.flush()

  # Receive ( t, r ) from attack target.
  return int( target_out.readline().strip() )

def attack() :
  # Select a hard-coded guess ...
  G = "0"

  # ... then interact with the attack target.
  errCode = interact( G )

  # Print all of the inputs and outputs.
  print "errorCode = %d" % ( errCode )

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
