#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"
#include "defiantcookie.h"

int main(int argc, char **argv){
  if(argc != 2){
    fprintf(stdout, "Usage: %s  <keyfile>\n",  argv[0]);
    return 0;
  } else {
    char* keyfile    = argv[1];
    int retcode;
    FILE *fp = NULL;

    bf_key_pair_t *key_pair =  NULL;


    fp = fopen(keyfile, "rb");

    if(fp != NULL){
      
      retcode = bf_read_key_pair(fp, &key_pair);
      fprintf(stderr, "bf_read_key_pair = %d\n", retcode);
      if(retcode == DEFIANT_OK){
        char *public_key = NULL;
        char *cookie = construct_cookie(key_pair);
        //bf_info_key_pair(stdout, key_pair);
        fprintf(stdout, "\n\n%s\n\n", cookie);
        
        public_key = public_key_cookie(cookie);

        fprintf(stdout, "\n\n%s\n\n", public_key);

        retcode = validate_cookie(cookie, key_pair);

        fprintf(stdout, "\n\n%d\n\n", retcode);

        free(public_key);
        free(cookie);
      }
      fclose(fp);
    } else {
      perror("Couldn't open keyfile for reading.");
    }
    
    


    bf_free_key_pair(key_pair);
    
  }
  
  return 0;

}

