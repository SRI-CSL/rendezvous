#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <ctype.h>


#include "defiantclient.h"


/* onion verification key -- needed by APACHE and CLIENT */
static EVP_PKEY *defiant_public_evp_pkey = NULL;

/* easy to vary the cipher; not sure if this makes anything more robust though */
static const EVP_CIPHER* defiant_cipher(int i){
  switch(i){
  case 0: return EVP_aes_256_cbc();
  case 1: return EVP_bf_cbc();
  case 2: return EVP_cast5_cbc();
  default: return EVP_aes_256_cbc();
  }
}

static int init_defiant_public_key(FILE* public_key_fp){
  int retcode;

  if(public_key_fp == NULL){
    retcode = DEFIANT_OK;
  } else if(public_key_fp != NULL && defiant_public_evp_pkey == NULL){
    defiant_public_evp_pkey = PEM_read_PUBKEY(public_key_fp, &defiant_public_evp_pkey, NULL, NULL);
    if(defiant_public_evp_pkey == NULL){ 
      retcode = DEFIANT_DATA;
    } else {
      retcode = DEFIANT_OK;
    }
  } else {
    retcode = DEFIANT_OK;
  }

  return retcode;
}

int defiant_lib_init(FILE* public_key_fp){
  return init_defiant_public_key(public_key_fp);
}

void defiant_lib_cleanup(void){
  if(defiant_public_evp_pkey != NULL){ 
    EVP_PKEY_free(defiant_public_evp_pkey);
    defiant_public_evp_pkey = NULL;
  }
}

static int defiant_verify_aux(EVP_PKEY *pub, char* data, int data_size, uchar* signature, unsigned int signature_sz);

static uchar* decrypt_aux(EVP_CIPHER_CTX *context, const uchar* input, int input_len, int *output_len);
static uchar* encrypt_aux(EVP_CIPHER_CTX *context, const uchar* input, int input_len, int *output_len);


int defiant_verify(FILE* public_key_fp, char* data, int data_size, uchar* signature, unsigned int signature_sz){
  int retcode = init_defiant_public_key(public_key_fp);
  if(retcode == DEFIANT_OK){
    return defiant_verify_aux(defiant_public_evp_pkey, data, data_size, signature, signature_sz);
  }
  return DEFIANT_DATA;
}


int defiant_verify_aux(EVP_PKEY *pub, char* data, int data_size, uchar* signature, unsigned int signature_sz){
  EVP_MD_CTX verify_cxt;
  int retcode = EVP_VerifyInit(&verify_cxt, EVP_sha1());
  if(retcode != 1){
    return DEFIANT_CRYPTO;
  }
  retcode = EVP_VerifyUpdate(&verify_cxt, data, data_size);
  if(retcode != 1){
    return DEFIANT_CRYPTO;
  } else {
    retcode = EVP_VerifyFinal(&verify_cxt, signature, signature_sz, pub);
    if((retcode != 1)){
      return DEFIANT_CRYPTO;
    }
  }
  EVP_MD_CTX_cleanup(&verify_cxt);
  return DEFIANT_OK;
}

 

uchar* defiant_pwd_encrypt(const char* password, const uchar* plaintext, int plaintextlen, int *output_len){
  bundle bag;
  bag.cipher = 0;
  memset(bag.key, 0, DEFIANT_MAX_KEY_LENGTH);
  memcpy(bag.key, password, strlen(password));
  memset(bag.iv, 0, DEFIANT_MAX_IV_LENGTH);
  /* could improvise with the iv too */
  return defiant_encrypt(&bag, plaintext, plaintextlen, output_len);
}

uchar* defiant_pwd_decrypt(const char* password, const uchar* data, int datalen, int *output_len){
  bundle bag;
  bag.cipher = 0;
  memset(bag.key, 0, DEFIANT_MAX_KEY_LENGTH);
  memcpy(bag.key, password, strlen(password));
  memset(bag.iv, 0, DEFIANT_MAX_IV_LENGTH);
  /* could improvise with the iv too */
  return defiant_decrypt(&bag, data, datalen, output_len);
}

uchar* defiant_encrypt(bundle* bag, const uchar* plaintext, int plaintextlen, int *output_len){
  uchar* retval = NULL;
  EVP_EncryptInit(&(bag->context), defiant_cipher(bag->cipher), bag->key, bag->iv);
  retval = encrypt_aux(&(bag->context), (uchar*)plaintext, plaintextlen, output_len);
  EVP_CIPHER_CTX_cleanup(&(bag->context));
  return retval;
}

uchar* defiant_decrypt(bundle* bag, const uchar* data, int datalen, int *output_len){
  uchar* retval = NULL;
  EVP_DecryptInit(&(bag->context), defiant_cipher(bag->cipher), bag->key, bag->iv);
  retval = decrypt_aux(&(bag->context), data, datalen, output_len);
  EVP_CIPHER_CTX_cleanup(&(bag->context));
  return retval;
}

#define MAGIC  16

uchar* encrypt_aux(EVP_CIPHER_CTX *context, const uchar* input, int input_len, int *output_len){
  uchar* output = (uchar*)calloc(input_len + EVP_CIPHER_CTX_block_size(context), sizeof(uchar));
  int i, incr, offset = 0, remainder = input_len % MAGIC;
  
  for(i = 0; i < input_len / MAGIC; i++){
    if(EVP_EncryptUpdate(context, &output[offset], &incr, &input[offset], MAGIC)){
      offset +=  incr;
    } 
  }
  
  if(remainder){
    if(EVP_EncryptUpdate(context, &output[offset], &incr, &input[offset], remainder)){
      offset +=  incr;
    } 
  }
  
  EVP_EncryptFinal(context, &output[offset], &incr);
  offset +=  incr;

  
  *output_len = offset;
  return output;
}

uchar* decrypt_aux(EVP_CIPHER_CTX *context, const uchar* input, int input_len, int *output_len){
  int length = input_len + EVP_CIPHER_CTX_block_size(context) + 1;
  uchar* output = (uchar*)calloc(length, sizeof(uchar));
  int offset, dangle;
  EVP_DecryptUpdate(context, output, &offset, input, input_len);
  if(!offset){
    free(output);
    *output_len = 0;
    return NULL;
  }
  if(EVP_DecryptFinal(context, &output[offset], &dangle) == 0){
    fprintf(stderr, "Padding wrong :-(  input length = %d\n", input_len);
    fprint64(stdout, input, input_len);
    free(output);
    *output_len = 0;
    return NULL;
  } else {
    offset += dangle;
  }
  output[offset] = '\0';
  *output_len = offset;
  return output;
}


int generate_random_key(uchar* key, int keylen){
  if(RAND_bytes(key, keylen) == 0){
    fprintf(stderr, "RAND_bytes failed. Error code = %ld\n",  ERR_get_error());
    return 0;
  }
  return 1;
}

int generate_random_iv(uchar* iv, int ivlen){
  if(RAND_pseudo_bytes(iv, ivlen) == 0){
    fprintf(stderr, "RAND_bytes failed. Error code = %ld\n",  ERR_get_error());
    return 0;
  }
  return 1;
}

int file2bytes_logging(FILE* logger, const char *cpath, int *bytesreadp, char ** bytesp){
  FILE		*f;
  int		errcode;
  uint64_t	len, num_read;
  char		*bytes;
  int debug = 1;
  if(logger == NULL){
    logger = stderr;
    debug = 0;
  }

  if ((cpath == NULL) || (bytesreadp == NULL) || (bytesp == NULL)) { 
    fprintf(logger, "file2bytes: bad args %d %d %d\n", cpath == NULL, bytesreadp == NULL, bytesp == NULL);
    fflush(logger);
    return DEFIANT_ARGS; 
  }

  f = fopen(cpath, "rb");
  if (f == NULL) { 
    fprintf(logger, "file2bytes: fopen(%s) failed; %s\n", cpath, strerror(errno));
    fflush(logger);
    return DEFIANT_FILE; 
  }

  /* Seek to the end */
  fseek(f, 0, SEEK_END);
  len = ftell(f);

  /* Start of file */
  fseek(f, 0, SEEK_SET);

  fprintf(logger, "file2bytes: reading %s file size = %" PRIu64 " bytes\n", cpath, len);
  fflush(logger);

  bytes = (char *)calloc(len, sizeof(char));
  if (bytes == NULL){ 
    fprintf(logger, "file2bytes: calloc failed\n");
    fflush(logger);
    return DEFIANT_MEMORY; 
  }

  num_read = fread(bytes, len, 1, f);
  errcode = errno;
  fclose(f);

  if (num_read != 1) {
    fprintf(logger, "file2bytes: fread failed: %d: %s\n", errcode, strerror(errcode));
    fflush(logger);
    return DEFIANT_FILE;
  }

  *bytesreadp = len;
  *bytesp = bytes;

  if(debug){
    fprintf(logger, "file2bytes: happy happy joy joy %d bytes read\n", (int)len);
    fflush(logger);
  }
  
  return DEFIANT_OK;
}

int file2bytes(const char *cpath, int *bytesreadp, char ** bytesp){
  return file2bytes_logging(NULL, cpath, bytesreadp,bytesp); 
}

/* could check for signals */
int bytes2file_logging(FILE* logger, const char *cpath, int bytes_sz, const char *bytes){
  FILE *f;
  int num_written;
  int errcode;
  int debug = 1;
  if(logger == NULL){
    logger = stderr;
    debug = 0;
  }


  if ((cpath == NULL) || (bytes_sz == 0) || (bytes == NULL)) { 
    fprintf(logger, "bytes2file: bad args %d %d %d\n", cpath == NULL, bytes_sz == 0, bytes == NULL);
    fflush(logger);
    return DEFIANT_ARGS; 
  }

  f = fopen(cpath, "wb");
  if (f == NULL){ 
    fprintf(logger, "bytes2file: fopen(%s) failed; %s\n", cpath, strerror(errno));
    fflush(logger);
    return DEFIANT_FILE; 
  }

  fprintf(logger, "bytes2file: writing %s file size = %u bytes\n", cpath, bytes_sz);
  fflush(logger);

  num_written = fwrite(bytes, bytes_sz, 1, f);
  errcode = errno;

  fclose(f);

  if (num_written != 1){
    fprintf(logger, "bytes2file: write failed: %d: %s\n", errcode, strerror(errcode));
    fflush(logger);
    return DEFIANT_FILE; 
  }

  if(debug){
    fprintf(logger, "bytes2file: happy happy joy joy: %d bytes written\n", (int)bytes_sz);
    fflush(logger);
  }

  return DEFIANT_OK;
}

int bytes2file(const char *cpath, int bytes_sz, const char *bytes){
  return bytes2file_logging(NULL, cpath, bytes_sz, bytes);
}



int ascii2unsigned(char* str, uchar* hash, int hashlen){
  int i;
  if((int)strlen(str) == 2 * hashlen){
    for(i = 0; i < hashlen; i++){
      unsigned int bytie;
      char b[] = {0, 0, 0};
      b[0] = str[2*i];
      b[1] = str[2*i + 1];
      sscanf(b, "%x", &bytie);
      hash[i] = bytie;
    }
    return 1;
  } else {
    fprintf(stderr, "ascii2unsigned: strlen=%d hashlen=%d\n", (int)strlen(str), hashlen);
    return 0;
  }
}

int unsigned2ascii(uchar* hash, int hashlen, char* str){
  int i;
  for(i = 0; i < hashlen; i++){
    sprintf(&str[2*i], "%02X", hash[i]);
  }
  return 1;
}


void fprintx(FILE* sink, uchar* key, int keylen){
  int i;
  for(i = 0; i < keylen; i++){
    fprintf(sink, "%02X", key[i]);
  }
  fprintf(sink, "\n");
}



void fprint64(FILE* sink, const uchar* key, int keylen){
  int len;
  char* b = enbase64(key, keylen, &len);
  fprintf(sink, "%s\n", b);
  free(b);
}

char *enbase64(const uchar *input, int length, int *outlen){
  int retcode;
  BIO *bmem, *b64 = NULL;
  BUF_MEM *bptr;
  char *buff = NULL;
  if(length <= 0){ goto cleanup; }
  b64 = BIO_new(BIO_f_base64());
  if(b64 == NULL){ goto cleanup; }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new(BIO_s_mem());
  if(bmem == NULL){ goto cleanup; }
  b64 = BIO_push(b64, bmem);
  retcode = BIO_write(b64, input, length);
  if(retcode <= 0){ goto cleanup; }
  retcode = BIO_flush(b64);
  if(retcode != 1){ goto cleanup; }
  BIO_get_mem_ptr(b64, &bptr);
  buff = (char *)calloc(bptr->length + 1, sizeof(char));
  if(buff == NULL){  goto cleanup; }
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = 0;
  if(outlen != NULL){ *outlen = bptr->length; }
  
 cleanup:
  if(b64 != NULL){ BIO_free_all(b64); }
  return buff;
}



uchar *debase64(const char *input, int *outlen){
  int bytes = 0;
  uchar *buffer = NULL;
  if(input != NULL){
    int length = strlen(input);
      BIO *b64  = NULL, *bmem = NULL; 
      b64 = BIO_new(BIO_f_base64());
      if(b64 != NULL){
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        buffer = (uchar *)calloc(length, sizeof(uchar));
        if(buffer != NULL){
          bmem = BIO_new_mem_buf((char *)input, length);
          bmem = BIO_push(b64, bmem);
          bytes = BIO_read(bmem, buffer, length);
        }
        BIO_free_all(b64);
      }
  }
  if(outlen != NULL){ *outlen = bytes; }
  return buffer;
}

/* comment out for non-silence */
/* #define DEBUG               */



/* nice simple search space: */
static int yahcharlen = 26;
static char yahchar[] = "abcdefghijklmnopqrstuvwxyz";

static int yahexcharlen = 62;
static char yahexchar[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";


/* should call srand(time(NULL)); prior */
void randomPassword(char *buff, int bufsz){
  int i;
   for(i = 0; i < bufsz - 1; i++){
    buff[i] =  yahchar[rand() % yahcharlen];
  }
  buff[bufsz - 1] = '\0';
}

void randomPasswordEx(char *buff, int bufsz, int lowerCase){
  if(lowerCase){
    randomPassword(buff, bufsz);
  } else {
    int i;
    for(i = 0; i < bufsz - 1; i++){
      buff[i] =  yahexchar[rand() % yahexcharlen];
    }
    buff[bufsz - 1] = '\0';
  }
}

/* returns 1 if true; 0 if false */
int isRandomPassword(char *buff, int bufsz){
  int i = 0;
  for(i = 0; i < bufsz; i++){
    int c = buff[i];
    if(!isalpha(c) || !islower(c)){ return 0; }
  }
  return 1;
}

/* returns 1 if true; 0 if false */
int isRandomPasswordEx(char *buff, int bufsz){
  int i = 0;
  for(i = 0; i < bufsz; i++){
    int c = buff[i];
    if(!isalnum(c)){ return 0; }
  }
  return 1;
}

/*
  currently assuming that the first is the correct one. i.e. that there aren't any short
  sha1 collisions. need to check this.

  you can tune how long this search takes by judicous choice of passwords. here is a rough guide (recent mac pro):
  1st letter  2nd letter   time
  a           a             2 minutes
  a           b             5 minutes
  a           c             7 minutes
  a           d             9 minutes

  soon the first two or three chars are going to be used for indexes of encryption routines.
  
 */

int search(const uchar* target, int target_len, char* solution, volatile long* progress){
  int i0, i1, i2, i3, i4, i5, i6, i7, diff;
  char password[DEFIANT_CLIENT_PASSWORD_LENGTH];
  uchar hash[20] = "";
  int depth = target_len < 20 ? target_len : 20;
  password[DEFIANT_CLIENT_PASSWORD_LENGTH - 1] = '\0';
  for(i0 = 0; i0 < yahcharlen; i0++){
    for(i1 = 0; i1 < yahcharlen; i1++){
      for(i2 = 0; i2 < yahcharlen; i2++){
        for(i3 = 0; i3 < yahcharlen; i3++){
          for(i4 = 0; i4 < yahcharlen; i4++){
            for(i5 = 0; i5 < yahcharlen; i5++){
              for(i6 = 0; i6 < yahcharlen; i6++){
                for(i7 = 0; i7 < yahcharlen; i7++){
                  password[0] = yahchar[i0];
                  password[1] = yahchar[i1];       
                  password[2] = yahchar[i2]; 
                  password[3] = yahchar[i3]; 
                  password[4] = yahchar[i4]; 
                  password[5] = yahchar[i5]; 
                  password[6] = yahchar[i6]; 
                  password[7] = yahchar[i7]; 
                  if(progress != NULL){ (*progress)++; }
                  SHA1((uchar*)password, DEFIANT_CLIENT_PASSWORD_LENGTH - 1, hash);
                  diff = memcmp(target, hash, depth);
                  if(diff == 0){
                    strcpy(solution, password);
                    return 1;
                  } else {
                    /* fprintf(stderr, "%s\n", password); */
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return 0;
}


char* defiant_pow(const char* hash64, const char* secret64, const char* cipher64, volatile long* progress){
  char* retval = NULL;
  int hash_len, secret_len, cipher_len;
  uchar *hash = debase64(hash64, &hash_len);
  uchar *secret = debase64(secret64, &secret_len);
  uchar *cipher = debase64(cipher64, &cipher_len);
  retval = defiant_pow_aux(hash, hash_len, secret, secret_len, cipher, cipher_len, progress);

  free(hash);
  free(secret);
  free(cipher);
  
  return retval;
  
}

char* defiant_pow_aux(const uchar* hash, int hash_len, const uchar* secret, int secret_len, const uchar* cipher, int cipher_len, volatile long* progress){
  char* retval = NULL;
  char password[DEFIANT_CLIENT_PASSWORD_LENGTH];
  /* do the work: search the simple space */
  int success = search(hash, hash_len, password, progress);
  if(success){
    bundle bag;
    int keys_len, plaintext_len;
    uchar* keys;
#ifdef DEBUG
    fprintf(stderr, "BINGO: %s of length %d!\n", password, (int)strlen(password));
#endif
    /* We currently use EVP_aes_256_cbc() */
    bag.cipher = 0;
    memset(bag.key, 0, DEFIANT_MAX_KEY_LENGTH);
    memcpy(bag.key, password, DEFIANT_CLIENT_PASSWORD_LENGTH);
    memset(bag.iv, 0, DEFIANT_MAX_IV_LENGTH);
    keys = defiant_decrypt(&bag, secret, secret_len, &keys_len);
    if(keys_len != DEFIANT_MAX_KEY_LENGTH + DEFIANT_MAX_IV_LENGTH){
      fprintf(stderr,  "defiant_pow: secret decrypts to length %d SHOULD BE %d\n", keys_len, DEFIANT_MAX_KEY_LENGTH + DEFIANT_MAX_IV_LENGTH);
    } else {
      memcpy(bag.key, keys, DEFIANT_MAX_KEY_LENGTH);
      memcpy(bag.iv, keys + DEFIANT_MAX_KEY_LENGTH, DEFIANT_MAX_IV_LENGTH);
      retval = (char *)defiant_decrypt(&bag, cipher, cipher_len, &plaintext_len);
      free(keys);
    }
  }
  return retval;
}



char** make_pow_puzzle(char *password, char* answer, int* argc){
  char** puzzlv = NULL;
  make_pow_puzzle_aux(password, answer, strlen(answer), argc, &puzzlv, NULL, 1);
  return puzzlv;
}

int make_pow_puzzle_aux(char *password, char* answer, size_t answer_size, int* puzzlcp, char*** puzzlvp, int** puzzlenvp, int base64){
  int retcode = DEFIANT_OK;
  char** puzzle = NULL;
  int puzzle_lengths[DEFIANT_CLIENT_PUZZLE_LENGTH] = {0, 0, 0};
  /*
  fprintf(stderr, "DEFIANT_MAX_KEY_LENGTH = %d\n", DEFIANT_MAX_KEY_LENGTH);
  fprintf(stderr, "DEFIANT_MAX_IV_LENGTH = %d\n", DEFIANT_MAX_IV_LENGTH);
  */
  if((password == NULL) || (answer == NULL)){
    return DEFIANT_ARGS;
  } else {
    bundle bag;
    uchar secret[DEFIANT_MAX_KEY_LENGTH + DEFIANT_MAX_IV_LENGTH];
    int secret_len = DEFIANT_MAX_KEY_LENGTH + DEFIANT_MAX_IV_LENGTH;
    int password_len = strlen(password);
    
    /* encrypted secret */
    uchar* cipheredsecret = NULL;
    int cipheredsecret_len;
    
    
    /* encrypted answer */
    uchar* cipheredanswer = NULL;
    int cipheredanswer_len;
    
    /* hash of password */
    uchar* password_hash = (uchar*)calloc(SHA_DIGEST_LENGTH, sizeof(char*));
    if(password_hash == NULL){ 
      retcode = DEFIANT_MEMORY;
      goto cleanup; 
    }
    /* "trunctate" password if too long */
    password_len = (password_len >= DEFIANT_CLIENT_PASSWORD_LENGTH) ? DEFIANT_CLIENT_PASSWORD_LENGTH : password_len;
    SHA1((uchar*)password, (int)strlen(password), password_hash);

    /* this is the secret; i.e. the key and iv we will use do encrypt the answer */
    generate_random_key(secret, DEFIANT_MAX_KEY_LENGTH + DEFIANT_MAX_IV_LENGTH);


    /* prepare to encrypt the secret */
    bag.cipher = 0;
    memset(bag.key, 0, DEFIANT_MAX_KEY_LENGTH);
    memcpy(bag.key, password, password_len);
    memset(bag.iv, 0, DEFIANT_MAX_IV_LENGTH);

    /* encrypt it */
    cipheredsecret = defiant_encrypt(&bag, secret, secret_len, &cipheredsecret_len);
    if(cipheredsecret == NULL){ 
      retcode = DEFIANT_CRYPTO; 
      goto cleanup; 
    }

    /* now use the secret to encrypt the answer */
    memcpy(bag.key, secret, DEFIANT_MAX_KEY_LENGTH);
    memcpy(bag.iv, secret + DEFIANT_MAX_KEY_LENGTH, DEFIANT_MAX_IV_LENGTH);

    cipheredanswer = defiant_encrypt(&bag, (uchar*)answer, (int)answer_size, &cipheredanswer_len);
    if(cipheredanswer == NULL){ 
      retcode = DEFIANT_CRYPTO; 
      goto cleanup; 
    }
    
    /* construct the result */
    puzzle = (char **)calloc(DEFIANT_CLIENT_PUZZLE_LENGTH, sizeof(char *));
    if(puzzle == NULL){ 
      retcode = DEFIANT_MEMORY;
      goto cleanup; 
    }

    if(base64){
      puzzle[0] = enbase64(password_hash, SHA_DIGEST_LENGTH, NULL);
      puzzle_lengths[0] = strlen(puzzle[0]);
      puzzle[1] = enbase64(cipheredsecret, cipheredsecret_len, NULL);
      puzzle_lengths[1] = strlen(puzzle[1]);
      puzzle[2] = enbase64(cipheredanswer, cipheredanswer_len, NULL);
      puzzle_lengths[2] = strlen(puzzle[2]);
    } else {
      puzzle[0] = (char *)password_hash;
      puzzle_lengths[0] =  SHA_DIGEST_LENGTH;
      puzzle[1] = (char *)cipheredsecret;
      puzzle_lengths[1] = cipheredsecret_len;
      puzzle[2] = (char *)cipheredanswer;
      puzzle_lengths[2] = cipheredanswer_len;
    }
    
  cleanup:
    if(base64){
      free(password_hash);
      free(cipheredsecret);
      free(cipheredanswer);
    }
  
  }

  if(retcode == DEFIANT_OK){
    /* package up & deliver the answers */
    if(puzzlenvp != NULL){
      int *lengths =  (int *)calloc(DEFIANT_CLIENT_PUZZLE_LENGTH, sizeof(int));
      if(lengths != NULL){
        int i;
        for(i = 0; i < DEFIANT_CLIENT_PUZZLE_LENGTH; i++){  lengths[i] = puzzle_lengths[i]; }
        *puzzlenvp = lengths;
      }
    }
    if(puzzlcp != NULL){ 
      *puzzlcp  = ((puzzle == NULL) ? 0 :  DEFIANT_CLIENT_PUZZLE_LENGTH); 
    }
    if(puzzlvp != NULL){ 
      *puzzlvp = puzzle; 
    }
    
  }

  return retcode;

}






int check_puzzle(char* password, char* answer, int puzzlec, char**puzzlev){
  return check_puzzle_aux(password, answer, strlen(answer), puzzlec, puzzlev);
}

int check_puzzle_aux(char* password, char* answer, int answer_size, int puzzlec, char**puzzlev){
  uchar password_hash[SHA_DIGEST_LENGTH];
  /* base 64 encoding of password hash */
  char* password64;
  int password64_len;
  /* baggage for encrypting and decrypting */
  bundle bag;
  /* target from decrypted puzzlev[1] */
  uchar *secret;
  int secret_len;

  /* encrypted secret */
  uchar* cipheredsecret = NULL;
  int cipheredsecret_len;

  /* round trip target for puzzlev[1] */
  char* cipheredsecret64 = NULL;
  int cipheredsecret64_len;
 
  char* encryptedsecret64 =  puzzlev[1];
  int encryptedsecret64_len = strlen(puzzlev[1]);
  int encryptedsecret_len;
  uchar* encryptedsecret = debase64(encryptedsecret64, &encryptedsecret_len);
  
  /* encrypted answer for comparison with puzzlev[2] */
  uchar* cipheredanswer = NULL;
  int cipheredanswer_len;
  int cipheredanswer64_len;
  char* cipheredanswer64;
  

  int password_len = strlen(password);
  /* "trunctate" password if too long */
  password_len = (password_len >= DEFIANT_CLIENT_PASSWORD_LENGTH) ? DEFIANT_CLIENT_PASSWORD_LENGTH : password_len;
  
  /* sanity check puzzle */
  if(DEFIANT_CLIENT_PUZZLE_LENGTH != puzzlec){  return -1; }
  
  /* PUZZLEV[0] */
  /* FIRST CHECK hash of password AGREES with puzzlev[0] */
  SHA1((uchar*)password, password_len, password_hash);
  password64 = enbase64(password_hash, SHA_DIGEST_LENGTH, &password64_len);
  if(password64_len != (int)strlen(puzzlev[0])){ return -100; }
  if(strncmp(password64, puzzlev[0], password64_len) != 0){ return -101; }
  
  free(password64);

  /* PUZZLE[1] */
  /* prepare to decrypt the secret */
  bag.cipher = 0;
  memset(bag.key, 0, DEFIANT_MAX_KEY_LENGTH);
  memcpy(bag.key, password, password_len);
  memset(bag.iv, 0, DEFIANT_MAX_IV_LENGTH);
  
  /* decrypt it */
  secret = defiant_decrypt(&bag, (uchar *)encryptedsecret, encryptedsecret_len, &secret_len);
  if(secret == NULL){ return -110; }
  if(secret_len != DEFIANT_MAX_KEY_LENGTH + DEFIANT_MAX_IV_LENGTH){ return -111; }
  
  /* check it */
  memset(bag.key, 0, DEFIANT_MAX_KEY_LENGTH);
  memcpy(bag.key, password, password_len);
  memset(bag.iv, 0, DEFIANT_MAX_IV_LENGTH);
  
  /* encrypt it */
  cipheredsecret = defiant_encrypt(&bag, secret, secret_len, &cipheredsecret_len);
  if(cipheredsecret == NULL){ return -112; }
  
  if(cipheredsecret_len != encryptedsecret_len){ return -113; }
  
  if(memcmp(cipheredsecret, encryptedsecret, encryptedsecret_len) != 0){ return -114; }

  cipheredsecret64 = enbase64(cipheredsecret, cipheredsecret_len, &cipheredsecret64_len);
  if(cipheredsecret64 == NULL){  return -115; }
  if(encryptedsecret64_len != cipheredsecret64_len){ return -116; }
  if(strncmp(encryptedsecret64, cipheredsecret64, cipheredsecret64_len) != 0){ return -117; }

  free(cipheredsecret64);
  free(encryptedsecret);
  free(cipheredsecret);
  
  /* PUZZLE[2] */
  /* now use the secret to encrypt the answer */
  memset(bag.key, 0, DEFIANT_MAX_KEY_LENGTH);
  memcpy(bag.key, secret, DEFIANT_MAX_KEY_LENGTH);
  memcpy(bag.iv, secret + DEFIANT_MAX_KEY_LENGTH, DEFIANT_MAX_IV_LENGTH);
  
  cipheredanswer = defiant_encrypt(&bag, (uchar*)answer, answer_size, &cipheredanswer_len);
  if(cipheredanswer == NULL){ return -120; }
  
  free(secret);
  
  cipheredanswer64 = enbase64(cipheredanswer, cipheredanswer_len, &cipheredanswer64_len);
  if(cipheredanswer64 == NULL){ return -121; }
  
  if(cipheredanswer64_len != (int)strlen(puzzlev[2])){  return -122; }
  
  if(strncmp(cipheredanswer64, puzzlev[2], cipheredanswer64_len) != 0){  return -123; }
  
  free(cipheredanswer);
  free(cipheredanswer64);
    

  return 0;

}


void free_puzzle( int puzzlec, char**puzzlev){
  int i;
  for(i = 0; i < puzzlec; i++){ free(puzzlev[i]); }
  free(puzzlev);
}

