#include <stdio.h>
#include <string.h>
#include "crc.h"
#include "platform.h"

static char str[] = "abracadabra_zim_zola_bin";

int main(int argc, char** argv){
  crc_t crc;
  char* input = str;
  if(argc > 1){
    input = argv[1];
  }
  
  crc = crc_init();
  crc = crc_update(crc, (unsigned char *)input, strlen(input));
  crc = crc_finalize(crc);
  
  fprintf(stdout, "crc(%s) = 0x%lx of size %" PRIsizet "\n", input, (unsigned long)crc, sizeof(crc));
  return 0;
}

