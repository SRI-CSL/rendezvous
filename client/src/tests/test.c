#include <stdio.h>
#include <string.h>

#include "defiantclient.h"


int main(int argc, char** argv){
  char password[DEFIANT_CLIENT_PASSWORD_LENGTH];
  char plaintext[256] = "http://bit.ly/xXsEwDcV"; 
  char**puzzle;
  int puzzlelen, i;
    


  /* generate a random password */
  srand(time(NULL));
  randomPassword(password, DEFIANT_CLIENT_PASSWORD_LENGTH);

  /* make it simpler */
  password[0] =  password[1]  = 'a';
  fprintf(stdout, "password = %s\n", password);
  fprintf(stdout, "plaintext = %s\n", plaintext);

  puzzle = make_pow_puzzle(password, plaintext, &puzzlelen);

  if((puzzle != NULL) && (puzzlelen == DEFIANT_CLIENT_PUZZLE_LENGTH)){
    fprintf(stdout, "./tool %s %s %s\n",  puzzle[0], puzzle[1], puzzle[2]);
    
    for(i = 0; i < DEFIANT_CLIENT_PUZZLE_LENGTH; i++){
      free(puzzle[i]);
    }
    free(puzzle);
  }

  return 0;
}



