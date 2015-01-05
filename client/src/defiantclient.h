#ifndef _DEFIANTCLIENT_H
#define _DEFIANTCLIENT_H

#if __llvm__
// Workaround DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <openssl/evp.h>

#include "defianterrors.h"
#include "defianttypes.h"

/* password length includes the terminating NULL */
#define DEFIANT_CLIENT_PASSWORD_LENGTH  9

/* number of binary blobs required by the pow puzzle */
#define DEFIANT_CLIENT_PUZZLE_LENGTH  3

/* password length for the captcha bundles */
#define DEFIANT_CAPTCHA_PASSWORD_LENGTH  8

/* length for the request reply protocol */
#define DEFIANT_REQ_REP_PASSWORD_LENGTH  16

/* temporary -- used to test the decryption by apache via validate_onion.c */
#define DEFIANT_TEST_PASSWORD  "What's New Pussy Cat?"

/* timeout in seconds -- tor hidden services don't leap out of bed */
#define DEFIANT_CURL_TIMEOUT  600

/* BUGFIX NOTES June 2013 
 *
 * In openssl 1.0.1  these number are:
 *
 * #define EVP_MAX_KEY_LENGTH		64
 * #define EVP_MAX_IV_LENGTH		16
 * 
 * In older versions they are:
 * 
 * #define EVP_MAX_KEY_LENGTH		32
 * #define EVP_MAX_IV_LENGTH		16
 * 
 * which makes the crypto routines here (in particular the pow ones)
 * sensitive to the versions on either side of the exchange
 * (the onion factory and the rendezvous (qt) client)
 * 
 * So we freeze them now.
 *
 */

#define DEFIANT_MAX_KEY_LENGTH		64
#define DEFIANT_MAX_IV_LENGTH		16


typedef struct _bundle {
  int cipher;
  uchar key[DEFIANT_MAX_KEY_LENGTH];
  uchar iv[DEFIANT_MAX_IV_LENGTH];
  EVP_CIPHER_CTX context;
} bundle;

#ifdef __cplusplus
extern "C" {
#endif
  
  int defiant_lib_init(FILE* public_key_fp);

  void defiant_lib_cleanup(void);

  int defiant_verify(FILE* public_key_fp, char* data, int data_size, uchar* signature, unsigned int signature_sz);

  uchar* defiant_pwd_encrypt(const char* password, const uchar* plaintext, int plaintextlen, int *output_len);
  uchar* defiant_pwd_decrypt(const char* password, const uchar* data, int datalen, int *output_len);

  uchar* defiant_encrypt(bundle* bag, const uchar* plaintext, int plaintextlen, int *output_len);
  uchar* defiant_decrypt(bundle* bag, const uchar* data, int datalen, int *output_len);
  
  int generate_random_key(uchar* key, int keylen);
  int generate_random_iv(uchar* iv, int ivlen);
    
  int freedom_encrypt(const uchar* data, int data_size, uchar** cipherp, int* cipher_szp);

  /* utility operations */
  int file2bytes(const char *cpath, int *bytesreadp, char** bytesp);
  int file2bytes_logging(FILE* logger, const char *cpath, int *bytesreadp, char** bytesp);
  int bytes2file(const char *cpath, int bytes_sz, const char *bytes);
  int bytes2file_logging(FILE* logger, const char *cpath, int bytes_sz, const char *bytes);
  
  /* hex triad UNUSED */
  int unsigned2ascii(uchar* hash, int hashlen, char* str);
  int ascii2unsigned(char* str, uchar* hash, int hashlen);
  void fprintx(FILE* sink, uchar* key, int keylen);
  
  /* base 64 triad USED */
  char *enbase64(const uchar *input, int length, int *outlen);
  uchar *debase64(const char *input, int *outlen);
  void fprint64(FILE* sink, const uchar* key, int keylen);
  
  
  void randomPassword(char *buff, int bufsz);
  void randomPasswordEx(char *buff, int bufsz, int lowerCase);
  int isRandomPassword(char *buff, int bufsz);
  int isRandomPasswordEx(char *buff, int bufsz);

  int search(const uchar* target, int target_len, char* solution, volatile long* progress);
  
  char* defiant_pow(const char* hash, const char* secret, const char* cipher, volatile long* progress);
  char* defiant_pow_aux(const uchar* hash, int hash_len, const uchar* secret, int secret_len, const uchar* cipher, int cipher_len, volatile long* progress);

  char** make_pow_puzzle(char *password, char* answer, int* argc);
  
  int make_pow_puzzle_aux(char *password, char* answer, size_t answer_size, int* argcp, char*** puzzlvp, int** puzzlenvp, int base64);
  
  int check_puzzle_aux(char* password, char* answer, int answer_size, int puzzlec, char**puzzlev);

  int check_puzzle(char* password, char* answer, int puzzlec, char**puzzlev);

  void free_puzzle( int puzzlec, char**puzzlev);
  
#ifdef __cplusplus
}	/*  extern "C" */

#endif /* __cplusplus */


#endif /* _DEFIANTCLIENT_H */
