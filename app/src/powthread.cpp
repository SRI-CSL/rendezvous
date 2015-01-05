#include "onionmanager.h"
#include "powthread.h"

#include "defiantclient.h"

#include <openssl/sha.h>

void PowThread::run(){
  size_t puzzle_size = ONION_PUZZLE_SIZE(onion);
  char* hash = ONION_PUZZLE(onion);
  int hash_len = SHA_DIGEST_LENGTH;
  char* secret = hash + SHA_DIGEST_LENGTH;
  int secret_len = puzzle_size - SHA_DIGEST_LENGTH;
  char* data = ONION_DATA(onion);
  size_t data_len = ONION_DATA_SIZE(onion);
  inner = defiant_pow_aux((uchar*)hash, hash_len, (uchar*)secret, secret_len, (uchar*)data, data_len, &manager->attempts);
}
