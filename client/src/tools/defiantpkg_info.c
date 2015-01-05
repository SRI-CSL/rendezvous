#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"

static const int localdebug = 0;

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
      if(localdebug){ fprintf(stderr, "bf_read_key_pair = %d\n", retcode); }
      fclose(fp);
      bf_info_key_pair(stdout, key_pair);
    } else {
      perror("Couldn't open keyfile for reading.");
    }
    
    bf_free_key_pair(key_pair);
    
  }
  
  return 0;

}
