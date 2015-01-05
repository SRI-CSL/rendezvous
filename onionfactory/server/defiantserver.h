#include <stdio.h>

#include "defiantclient.h"

int defiantserver_lib_init(FILE* private_key_fp);

void defiantserver_lib_cleanup();

int defiant_sign(FILE* private_key_fp, char* data, int data_size, uchar** signaturep, unsigned int* signature_szp);



