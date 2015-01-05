#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"
#include "defiant_params.h"



int main(int argc, char **argv){
  if(argc != 2){
    fprintf(stdout, "Usage: %s  <keyfile>\n",  argv[0]);
    return 0;
  } else {
    char* keyfile    = argv[1];
    int retcode;
    FILE *fp = NULL;

    bf_params_t *params_64  =  NULL;
    bf_params_t *params_bin =  NULL;

    retcode = bf_char64_to_params(defiant_params_P, defiant_params_Ppub, &params_64);

    if(retcode == DEFIANT_OK){

      fp = fopen(keyfile, "rb");

      if(fp != NULL){
        retcode = bf_read_params(fp, &params_bin);
        fprintf(stderr, "bf_read_params = %d\n", retcode);
        fclose(fp);
        if(retcode == DEFIANT_OK){
          int cmpP = element_cmp(params_64->P, params_bin->P);
          int cmpB = element_cmp(params_64->Ppub, params_bin->Ppub);
          bf_info_params(stderr, params_bin);
          bf_info_params(stderr, params_64);
          fprintf(stderr, "params P cmp: %d\n", cmpP);
          fprintf(stderr, "params Ppub cmp: %d\n", cmpB);
        } else {
          fprintf(stderr, "bf_read_params = %d\n", retcode);
        }
      } else {
        perror("Couldn't open keyfile for reading.");
      }
      
    } else {
      fprintf(stderr, "bf_char64_to_params = %d\n", retcode);
    }
    
    bf_free_params(params_bin);
    bf_free_params(params_64);
    
  }
  
  return 0;

}
