#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"
#include "platform.h"

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
      fclose(fp);
      if(retcode == DEFIANT_OK){
        char *public_key = NULL, *b64Qid = NULL, *b64Did = NULL;
        retcode = bf_key_pair_to_char64(&public_key, &b64Qid, &b64Did, key_pair);
        if(retcode == DEFIANT_OK){
          fprintf(stdout, "%s\n%s\n%s\n", public_key, b64Qid, b64Did);
          fprintf(stderr, "%" PRIsizet " %" PRIsizet " %" PRIsizet "\n",  strlen(public_key), strlen(b64Qid), strlen(b64Did));
          //bf_info_key_pair(stdout, key_pair);
        }
      } else {
        perror("Couldn't open keyfile for reading.");
      }
      
      bf_free_key_pair(key_pair);
    }
  }
  
  return 0;

}
