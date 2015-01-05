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

    bf_master_key_t *master_key =  NULL;


    fp = fopen(keyfile, "rb");

    if(fp != NULL){
      retcode = bf_read_master_key(fp, &master_key);
      fprintf(stderr, "bf_read_master_key = %d\n", retcode);
      fclose(fp);
      bf_info_master_key(stdout, master_key);
    } else {
      perror("Couldn't open keyfile for reading.");
    }
    
    bf_free_master_key(master_key);
    
  }
  
  return 0;

}
