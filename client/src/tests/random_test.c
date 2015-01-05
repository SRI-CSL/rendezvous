#include <stdio.h>
#include <string.h>

#include "defiantclient.h"
#include "makeargv.h"




int main(int argc, char** argv){
  char password[DEFIANT_CLIENT_PASSWORD_LENGTH];
  char plaintext[256] = "http://bit.ly/xXsEwDcV"; 
  char**puzzle;
  int puzzlelen;
  long counter = 0;

  srand(time(NULL));
  
  while(1){
    counter++;
    if(counter < 0){ break; }

    if(counter > 10){ break; }  

    /* generate a random password */
    randomPassword(password, DEFIANT_CLIENT_PASSWORD_LENGTH);

    puzzle = make_pow_puzzle(password, plaintext, &puzzlelen);
    
    if((puzzle != NULL) && (puzzlelen == DEFIANT_CLIENT_PUZZLE_LENGTH)){
      int error;
      if((error = check_puzzle(password, plaintext, puzzlelen, puzzle)) < 0){
        fprintf(stdout, "ERROR %d %s %s %s %s\n",  error, password, puzzle[0], puzzle[1], puzzle[2]);
        return 0;
      }
      fprintf(stdout, "[%ld]: OK %s %s %s %s\n",  counter, password, puzzle[0], puzzle[1], puzzle[2]);
      freeargv(puzzlelen, puzzle);
    } else {
      break;
    }
  }

  return 0;
}


