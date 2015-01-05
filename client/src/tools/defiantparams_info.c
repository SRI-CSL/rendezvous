#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"

int main(int argc, char **argv){
  if(argc != 2){
    fprintf(stdout, "Usage: %s  <keyfile>\n",  argv[0]);
    return 0;
  } else {
    char* keyfile    = argv[1];
    int retcode;
    FILE *fp = NULL;

    bf_params_t *params =  NULL;


    fp = fopen(keyfile, "rb");

    if(fp != NULL){
      retcode = bf_read_params(fp, &params);
      fprintf(stderr, "bf_read_params = %d\n", retcode);
      fclose(fp);
      bf_info_params(stderr, params);
      bf_info_params64(stderr, params);
    } else {
      perror("Couldn't open keyfile for reading.");
    }
    
    bf_free_params(params);
    
  }
  
  return 0;

}
