#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include "defiantclient.h"


/*
 *   
 *  ./tool64 /maoMWkpW4t4KffxvvQ67EJiWWY= OZOe6xGCASm0uHaU/wHGSJ1dcw2ot2oP53imgY1jQjOZuGb46vPgURt+/4fpsFv9YWX3MrQcxqvpGpTE86acVA== 6TPCFVqukfGMFEBSvBHZkqvOwSLPsgUGui3Ua1m811U=
 *
 */

int main(int argc, char** argv){
  if(argc != 4){ 
    fprintf(stderr, "Usage: %s hash secret cipher\n", argv[0]);
    return 0;
  } else {
    char *nexthop = defiant_pow(argv[1], argv[2], argv[3], NULL);
    if(nexthop != NULL){
      fprintf(stderr, "%s\n", nexthop);
      free(nexthop);
    } else {
      fprintf(stderr, "nope.\n");
    }
  }
  return 0;
  
}



