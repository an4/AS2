#include "attack.h"
#include "string.h"

#define BUFFER_SIZE ( 256 )

/** Error codes */
#define SUCCESS 0
#define ERROR1 1
#define ERROR2 2
// Message out of range
#define M_RANGE 3
// Ciphertext out of range
#define C_RANGE 4
// Message too long mLen > k - 2hLen - 2
#define M_LENGHT 5
// Ciphertext does not match length of N
#define C_LENGHT 6
// Ciphertext does not match the length of the hash function output
#define CH_LENGHT 7
/** */

pid_t pid        = 0;    // process ID (of either parent or child) from fork

int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

void pad_ciphertext(const char* cipher, char* output) {
    int length = BUFFER_SIZE - strlen(cipher);
    sprintf(output,"%s%0*d", cipher, length, 0);
}

void interact(        int* errCode,
               const char* ciphertext ) {
    // Ciphertext needs to match modulus length
    char padded_ciphertext[256];
    pad_ciphertext(ciphertext, padded_ciphertext);

    // Send ciphertext to attack target.
    fprintf( target_in, "%s\n", padded_ciphertext );  fflush( target_in );

    // Receive errCode from attack target.
    fscanf( target_out, "%d", errCode );
}

void attack() {
  // Select a hard-coded guess ...
  char* G = "00";

  int   errCode;

  // ... then interact with the attack target.
  interact( &errCode, G);

  printf( "errCode = %d\n", errCode );

}

void cleanup( int s ){
  // Close the   buffered communication handles.
  fclose( target_in  );
  fclose( target_out );

  // Close the unbuffered communication handles.
  close( target_raw[ 0 ] );
  close( target_raw[ 1 ] );
  close( attack_raw[ 0 ] );
  close( attack_raw[ 1 ] );

  // Forcibly terminate the attack target process.
  if( pid > 0 ) {
    kill( pid, SIGKILL );
  }

  // Forcibly terminate the attacker      process.
  exit( 1 );
}

int main( int argc, char* argv[] ) {
  // Ensure we clean-up correctly if Control-C (or similar) is signalled.
  signal( SIGINT, &cleanup );

  // Create pipes to/from attack target; if it fails the reason is stored
  // in errno, but we'll just abort.
  if( pipe( target_raw ) == -1 ) {
    abort();
  }
  if( pipe( attack_raw ) == -1 ) {
    abort();
  }

  switch( pid = fork() ) {
    case -1 : {
      // The fork failed; reason is stored in errno, but we'll just abort.
      abort();
    }

    case +0 : {
      // (Re)connect standard input and output to pipes.
      close( STDOUT_FILENO );
      if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
        abort();
      }
      close(  STDIN_FILENO );
      if( dup2( target_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
        abort();
      }

      // Produce a sub-process representing the attack target.
      execl( argv[ 1 ], NULL );

      // Break and clean-up once finished.
      break;
    }

    default : {
      // Construct handles to attack target standard input and output.
      if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL ) {
        abort();
      }
      if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) {
        abort();
      }

      // Execute a function representing the attacker.
      attack();

      // Break and clean-up once finished.
      break;
    }
  }

  // Clean up any resources we've hung on to.
  cleanup( SIGINT );

  return 0;
}
