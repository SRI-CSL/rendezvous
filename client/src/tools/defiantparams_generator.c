#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"

int main(int argc, char **argv){
  if(argc != 3){
    fprintf(stdout, "Usage: %s <masterkeyfile> <outfile>\n",  argv[0]);
    return 0;
  } else {
    char* masterfile = argv[1];
    char* paramsfile = argv[2];
    int retcode;
    FILE *fp = NULL;

    bf_master_key_t* master_key = NULL;
    bf_params_t *params =  NULL;

    fp = fopen(masterfile, "rb");

    if(fp != NULL){
      retcode = bf_read_master_key(fp, &master_key);
      fprintf(stderr, "bf_read_master_key = %d\n", retcode);
      fclose(fp);
    } else {
      perror("Couldn't open masterkey for writing.");
    }

    if(master_key != NULL){
      params = bf_create_params(master_key);
      if(params != NULL){
        fp = fopen(paramsfile, "wb");
        if(fp != NULL){
          retcode = bf_write_params(fp, params);
          fprintf(stderr, "bf_write_params = %d\n", retcode);
          fclose(fp);
        } else {
          perror("Couldn't open keyfile for writing.");
        }
      } else {
        fprintf(stderr, "bf_create_params returned NULL\n");
      }
    } else {
      fprintf(stderr, "master_key is NULL\n");
    }

    bf_free_params(params);
    bf_free_master_key(master_key);
    
  }
  
  return 0;

}
