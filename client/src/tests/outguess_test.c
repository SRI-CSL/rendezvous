#include <stdlib.h>
#include <errno.h>

#include "onion.h"
#include "jpeg_steg.h"
#include "defianterrors.h"
#include "defiantclient.h"



/* UNDER CONSTRUCTION SEPTEMBER 18 2012 */


int main(int argc, char** argv){
  char *bytes = NULL;
  size_t byte_sz = 0;
  if((argc < 3) || (argc > 5)){
    fprintf(stderr, "Usage: %s encrypted_onion_file image_file [intermediate_file extracted_data] %d\n", argv[0], argc);
    exit(1);
  } else {
    char* onion = NULL;
    char* onion_file = argv[1];
    int onion_size;
    int errcode = file2bytes(onion_file, &onion_size, &onion);
    if(errcode != DEFIANT_OK){
      fprintf(stderr, "%s: couldn't read onion file %s, errcode = %d\n", argv[0], onion_file, errcode);
      exit(1);
    } else {
      char* image_file = argv[2];
      errcode  = embed(NULL, onion,  onion_size, image_file, &bytes, &byte_sz);
      if(errcode != DEFIANT_OK){
        fprintf(stderr, "%s: embed failed, returned %d\n", argv[0], errcode);
        exit(1);
      } else {
        fprintf(stderr, "%s: embed OK, image_size = %zu\n", argv[0], byte_sz);
        if(argc >= 4){
          char * intermediate = argv[3]; 
          FILE* int_fp = fopen(intermediate, "wb");
          if(int_fp == NULL){
            fprintf(stderr, "%s: couldn't open %s for writing, errno = %d\n", argv[0], intermediate,  errno);
          } else {
            int bytes_written = fwrite(bytes, sizeof(char), byte_sz, int_fp);
            fclose(int_fp);
            fprintf(stderr, "%s: wrote %d bytes to %s\n", argv[0], bytes_written, intermediate);
         }
        }


        {
          char* xonion = NULL;
          size_t xonion_size;
          errcode =  extract(NULL, bytes, byte_sz,  &xonion, &xonion_size);

          if(errcode != DEFIANT_OK){
            fprintf(stderr, "%s: extract failed, returned %d\n", argv[0], errcode);
            exit(1);
          } else {
            fprintf(stderr, "%s: extract OK, payload size = %zu\n", argv[0], xonion_size);
            if(argc >= 5){
              char * payload = argv[4]; 
              FILE* payload_fp = fopen(payload, "wb");
              if(payload_fp == NULL){
                fprintf(stderr, "%s: couldn't open %s for writing, errno = %d\n", argv[0], payload,  errno);
              } else {
                int bytes_written = fwrite(xonion, sizeof(char), xonion_size, payload_fp);
                fclose(payload_fp);
                fprintf(stderr, "%s: wrote %d bytes to %s\n", argv[0], bytes_written, payload);
              }
            }
          }
          free(xonion);
        }
        free(onion);
        free(bytes);
      }
    }
  }
  return 0;
}
