#include <stdio.h>
#include <string.h>

#include "defiantclient.h"


int main(int argc, char** argv){
  char password[DEFIANT_CLIENT_PASSWORD_LENGTH];
  if(argc != 2){
    fprintf(stderr, "Usage: %s [target url]\n", argv[0]);
    return 0;
  } else {
    char**puzzle;
    int puzzlelen, i;
    


    /* generate a random password */
    srand(time(NULL));
    randomPassword(password, DEFIANT_CLIENT_PASSWORD_LENGTH);
    
    /* make it simpler */
    password[0] =  password[1]  = 'a';
    fprintf(stdout, "password = %s\n", password);
    fprintf(stdout, "plaintext = %s\n", argv[1]);
    
    puzzle = make_pow_puzzle(password, argv[1], &puzzlelen);
    
    if((puzzle != NULL) && (puzzlelen == DEFIANT_CLIENT_PUZZLE_LENGTH)){
      fprintf(stdout, "./tool %s %s %s\n",  puzzle[0], puzzle[1], puzzle[2]);
      for(i = 0; i < DEFIANT_CLIENT_PUZZLE_LENGTH; i++){
        free(puzzle[i]);
      }
      free(puzzle);
    }
    
    return 0;
  }
  
}


