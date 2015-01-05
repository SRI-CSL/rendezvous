#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"

static const int localdebug = 0;

int main(int argc, char **argv){
  if(argc != 4){
    fprintf(stdout, "Usage: %s <masterkeyfile> <host url> <outputfile>\n",  argv[0]);
    return 0;
  } else {
    char* masterfile = argv[1];
    char* public_key = argv[2];
    char* keyfile    = argv[3];
    int retcode;
    FILE *fp = NULL;

    bf_master_key_t* master_key = NULL;
    bf_key_pair_t *key_pair =  NULL;

    fp = fopen(masterfile, "rb");

    if(fp != NULL){
      retcode = bf_read_master_key(fp, &master_key);
      if(localdebug){ fprintf(stderr, "bf_read_master_key = %d\n", retcode); }
      fclose(fp);
    } else {
      perror("Couldn't open masterkey for writing.");
    }

    if(master_key != NULL){
      key_pair = bf_create_key_pair(public_key, master_key);
      if(key_pair != NULL){
        fp = fopen(keyfile, "wb");
        if(fp != NULL){
          retcode = bf_write_key_pair(fp, key_pair);
          if(localdebug){ fprintf(stderr, "bf_write_key_pair = %d\n", retcode); }
          fclose(fp);
        } else {
          perror("Couldn't open keyfile for writing.");
        }
      } else {
        fprintf(stderr, "bf_create_key_pair returned NULL\n");
      }
    } else {
      fprintf(stderr, "master_key is NULL\n");
    }

    bf_free_key_pair(key_pair);
    bf_free_master_key(master_key);
    
  }
  
  return 0;

}
