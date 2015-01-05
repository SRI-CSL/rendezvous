#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"


int main(int argc, char **argv){

  if(argc != 2){
    fprintf(stdout, "Usage: %s <outfile>\n",  argv[0]);
    return 0;
  } else {
    char *masterfile = argv[1];
    bf_master_key_t* master_key = bf_create_master_key();

    if(master_key != NULL){
      FILE* fp = fopen(masterfile, "wb");
      if(fp != NULL){
        int retcode = bf_write_master_key(fp, master_key);
        fprintf(stderr, "bf_write_master_key = %d\n", retcode);
        fclose(fp);
      } else {
        perror("Couldn't open masterfile for writing");
      }
    } else {
      fprintf(stderr, "bf_create_master_key returned NULL\n");
    }
    
    bf_free_master_key(master_key);

  }

  return 0;

}
