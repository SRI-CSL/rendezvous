#include <stdio.h>
#include <string.h>

#include "defiantclient.h"
#include "platform.h"

#if 0

int main(int argc, char** argv){
  char *b64i = "BTpVI5CR9+sHDx9ik9VzRMQRvmY8FhAwKE08NlHf42EhvYh+t9uWFWCkKUGv8Fy9vl3KfznDFrg1dRbSLJNsi8IGxzjNNFcEzR8lF4WP24pwBcVZmAq19aSFwzHJ/cb74mgGPZIEKVPoNWOfWYYx59A4BRO3Lh7rWLeD/Lc6jCcA";
  int osz = 0;
  char *b64o = NULL;
  
  b64o = (char *)debase64(b64i, &osz);

  fprintf(stdout, "b64o = %s of length %ld\n", b64o, strlen(b64o));

  free(b64o);

  return 0;
}

#else

int main(int argc, char** argv){
  char *b64i = "BTpVI5CR9+sHDx9ik9VzRMQRvmY8FhAwKE08NlHf42EhvYh+t9uWFWCkKUGv8Fy9vl3KfznDFrg1dRbSLJNsi8IGxzjNNFcEzR8lF4WP24pwBcVZmAq19aSFwzHJ/cb74mgGPZIEKVPoNWOfWYYx59A4BRO3Lh7rWLeD/Lc6jCcA";
  int osz = 0;
  char *b64o = NULL;
  
  b64o = (char *)enbase64((uchar *)b64i, strlen(b64i), &osz);

  fprintf(stdout, "b64o = %s of length %" PRIsizet "\n", b64o, strlen(b64o));

  free(b64o);

  return 0;
}

#endif
