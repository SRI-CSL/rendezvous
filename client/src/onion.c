#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#ifndef _WIN32
/* for waitpid */       
#include <sys/types.h>
#include <sys/wait.h>
#endif

#include <openssl/sha.h>


#include "onion.h"
#include "defiantclient.h"
#include "defiantconstants.h"

const uint8_t onion_magic[6] = "0N10N\0";

/* Avoid pointer-math-alignment issues, use memcpy() */
static uint32_t onioncolcount(onion_t onion_in);
uint32_t onioncolcount(onion_t onion_in) {
  uint32_t count;

  memcpy(&count, ONION_PUZZLE(onion_in), sizeof count);

  /* Onions are stored in network byte order */
  return ntohl(count);
}

void free_onion(onion_t o){ free(o); }

onion_t alloc_onion(int type, size_t psz, size_t dsz, void *p, void *d){
  size_t osz = sizeof(onion_header_t) + psz + dsz;
  onion_t o = (onion_t)calloc(1, osz);
  if(o == NULL){ 
    return NULL; 
  } else {
    onion_header_t *oh = (onion_header_t *)o;
    char *buff = (char*)o;
    char *pbuff = buff + sizeof(onion_header_t);
    char *dbuff = pbuff + psz;
    /*
    fprintf(stderr, "sizeof(onion_magic) = %" PRIsizet ", sizeof(oh->magic) = %" PRIsizet "\n",
		sizeof onion_magic, sizeof oh->magic);
    */
    assert(sizeof onion_magic == sizeof oh->magic);
    memcpy(oh->magic, onion_magic, sizeof onion_magic);
    assert(ONION_IS_ONION(oh));
    oh->onion_type = htons(type);	/* 16 bit */
    oh->puzzle_size = htonl(psz);	/* 32 bit */
    oh->data_size = htonl(dsz);		/* 32 bit */
    if(p != NULL){ memcpy(pbuff, p, psz); }
    if(d != NULL){ memcpy(dbuff, d, dsz); }
    return o;
  }
}



 
/* doesn't verify -- use verify_onion for that */
int peel_signed_onion(onion_t onion_in, onion_t *onion_outp){
  if((onion_in == NULL) || (onion_outp == NULL) || (ONION_TYPE(onion_in) != SIGNED)){ 
    return DEFIANT_ARGS; 
  } else {
    size_t data_size = ONION_DATA_SIZE(onion_in);
    onion_t candidate = ONION_DATA(onion_in);
    size_t candidate_sz = ONION_SIZE(candidate);
    if(data_size != candidate_sz){
      return DEFIANT_DATA;
    } else {
      onion_t onion_out = alloc_onion(ONION_TYPE(candidate), ONION_PUZZLE_SIZE(candidate), ONION_DATA_SIZE(candidate), ONION_PUZZLE(candidate), ONION_DATA(candidate));
      if(onion_out == NULL){
        return DEFIANT_MEMORY;
      } else {
        *onion_outp = onion_out;
        return DEFIANT_OK;
      }
    }
  }
}

int peel_captcha_onion(char* secret, onion_t onion_in, onion_t *onion_outp){
  if((secret == NULL) || (onion_in == NULL) || (onion_outp == NULL) || (ONION_TYPE(onion_in) != CAPTCHA)){ 
    return DEFIANT_ARGS; 
  } else {
    char* data = ONION_DATA(onion_in);
    size_t data_size = ONION_DATA_SIZE(onion_in);
    int decrypted_size = 0;
    uchar *decrypted = defiant_pwd_decrypt(secret, (uchar*)data, data_size, &decrypted_size);
    if(decrypted_size == 0){
      return DEFIANT_DATA;
    } else {
      onion_t candidate = decrypted;
      size_t candidate_size = ONION_SIZE(candidate);
      if(decrypted_size != (int)candidate_size){
        return DEFIANT_DATA;
      } else {
        *onion_outp = candidate;
        return DEFIANT_OK;
      }
    }
  }
}

int peel_pow_onion(onion_t onion_in, onion_t *onion_outp){
  if((onion_outp == NULL) || (onion_in == NULL) || (ONION_TYPE(onion_in) != POW)){
    return DEFIANT_ARGS;
  } else {
    size_t puzzle_size = ONION_PUZZLE_SIZE(onion_in);
    char* hash = ONION_PUZZLE(onion_in);
    int hash_len = SHA_DIGEST_LENGTH;
    char* secret = hash + SHA_DIGEST_LENGTH;
    int secret_len = puzzle_size - SHA_DIGEST_LENGTH;
    char* data = ONION_DATA(onion_in);
    size_t data_len = ONION_DATA_SIZE(onion_in);
    onion_t onion_out = defiant_pow_aux((uchar*)hash, hash_len, (uchar*)secret, secret_len, (uchar*)data, data_len, NULL);
    if(onion_out != NULL){
      *onion_outp = onion_out;
      return DEFIANT_OK;
    }
    return DEFIANT_CRYPTO;
  }
}

int peel_collection_onion(onion_t onion_in, int* onioncp, onion_t** onionvp){
  if((onion_in == NULL) || (onioncp == NULL)  || (onionvp == NULL) || (ONION_TYPE(onion_in) != COLLECTION)){ 
    return DEFIANT_ARGS; 
  } else {
    int i, onionc = onioncolcount(onion_in);
    size_t offset = 0;
    char* onionvector = (char *)(ONION_DATA(onion_in));
    onion_t *onionv = (onion_t*)calloc(onionc, sizeof(onion_t));
    if(onionv == NULL){ return DEFIANT_MEMORY; }
    for(i = 0; i < onionc; i++){
      char* onionptr = &onionvector[offset];
      onion_t onion = (onion_t)(onionptr);
      size_t onion_size = ONION_SIZE(onion);
      char* onion_copy = (char *)calloc(onion_size, sizeof(char));
      if(onion_copy == NULL){ return DEFIANT_MEMORY; }
      memcpy(onion_copy, onionptr, onion_size);
      onionv[i] = onion_copy;
      offset += onion_size;
    }
    *onioncp = onionc;
    *onionvp = onionv;
    return DEFIANT_OK;
  }
}

void info_onion(FILE* fptr, onion_t onion){
  uint16_t	onion_type;
  uint32_t	osz, psz, dsz;

  if (!ONION_IS_ONION(onion)) {
    fprintf(fptr, "Onion is not an onion - Magic incorrect\n");
    return;
  }

  onion_type = ONION_TYPE(onion);
  osz = ONION_SIZE(onion);
  psz = ONION_PUZZLE_SIZE(onion);
  dsz = ONION_DATA_SIZE(onion);

  fprintf(fptr, "[%u] { onion_type:%u puzzle_size: %u data_size:%u }\n", osz, onion_type, psz, dsz);

  if(onion_type == BASE){
    char *buff = (char*)onion;
    char *dbuff = buff + sizeof(onion_header_t) + psz;
    fprintf(fptr, "%s\n", dbuff);
  } else if(onion_type == POW){
    fprint64(fptr, (uchar *)ONION_PUZZLE(onion), psz);
    fprint64(fptr, (uchar *)ONION_DATA(onion), dsz);
  } else if(onion_type == CAPTCHA){
    fprint64(fptr, (uchar *)ONION_DATA(onion), dsz);
  } else if(onion_type == SIGNED){
    fprint64(fptr, (uchar *)ONION_PUZZLE(onion), psz);
  } else if(onion_type == COLLECTION){
    uint32_t count = onioncolcount(onion);
    fprintf(fptr, "onion of size %u is a collection of %u onions weighing %u bytes\n", osz, count, dsz);
  }
}


int file2onion(char* path, onion_t *onionp){
  int fd = open(path, O_RDONLY);
  if(fd == -1){
    return DEFIANT_FILE;
  } else {
    int retcode = read_onion(fd, onionp);
    close(fd);
    return retcode;
  }
}

int onion2file(char* path, onion_t onion){
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);
  if(fd == -1){
    return DEFIANT_FILE;
  } else {
    int retcode = write_onion(fd, onion);
    close(fd);
    return retcode;
  }
}





int read_onion(int fd, onion_t *onionp){
  int retval = DEFIANT_OK;
  onion_header_t headers;
  size_t bytesread = read(fd, &headers, sizeof( onion_header_t ));
  if(bytesread !=  sizeof( onion_header_t )){ 
    if(bytesread == 0){ 
      return DEFIANT_EOF;
    } else if(bytesread == (size_t)-1){
      fprintf(stderr, "header read failed; check errno\n");
      retval = DEFIANT_FILE; 
    } else {
      fprintf(stderr, "truncated file?\n");
      retval = DEFIANT_FILE; 
    }
  } else {
    int onion_type = ONION_TYPE(&headers);
    size_t psz = ONION_PUZZLE_SIZE(&headers);
    size_t dsz = ONION_DATA_SIZE(&headers);
    onion_t onion = alloc_onion(onion_type, psz, dsz, NULL, NULL);
    char *buff = (char*)onion;
    char *pbuff = buff + sizeof(onion_header_t);
    char *dbuff = pbuff + psz;
    bytesread = read(fd, pbuff, psz);
    if(bytesread != psz){
      retval = DEFIANT_FILE; 
    } else {
      bytesread = read(fd, dbuff, dsz);
      if(bytesread != dsz){
        retval = DEFIANT_FILE; 
      } 
    }
    if(retval == DEFIANT_OK){
      *onionp = onion;
    } else {
      free_onion(onion);
      *onionp = NULL;
    }
  }
  return retval;
}


int write_onion(int fd, onion_t onion){
  onion_header_t *oh = (onion_header_t *)onion;
  char *buff = (char*)onion;
  char *pbuff = buff + sizeof(onion_header_t);
  char *dbuff = pbuff + ONION_PUZZLE_SIZE(oh);
  size_t byteswritten = write(fd, oh, sizeof( onion_header_t ));
  if(byteswritten != sizeof( onion_header_t )){ return DEFIANT_FILE; }
  byteswritten = write(fd, pbuff, ONION_PUZZLE_SIZE(oh));
  if(byteswritten != ONION_PUZZLE_SIZE(oh)){ return DEFIANT_FILE; }
  byteswritten = write(fd, dbuff, ONION_DATA_SIZE(oh));
  if(byteswritten != ONION_DATA_SIZE(oh)){ return DEFIANT_FILE; }
  return DEFIANT_OK;
}


int verify_onion(FILE* public_key_fp, onion_t onion){
  if((onion == NULL) || (ONION_TYPE(onion) != SIGNED)){ 
    return DEFIANT_ARGS;
  } else {
    return defiant_verify(public_key_fp, ONION_DATA(onion),  ONION_DATA_SIZE(onion), (uchar *)ONION_PUZZLE(onion), ONION_PUZZLE_SIZE(onion));
  }
}

int make_onion(int type, size_t psz, size_t dsz, void *p, void *d, onion_t *onionp){
  switch(type){
  case BASE:    return make_base_onion(psz, dsz, p, d, onionp);
  case POW:     return make_pow_onion(dsz, d, onionp);
  case CAPTCHA:  return make_captcha_onion(dsz, d, onionp);
  case SIGNED:
  default: return -type;
  }
}

int make_base_onion(size_t psz, size_t dsz, void *p, void *d, onion_t *onionp){
  onion_t onion = alloc_onion(BASE, psz, dsz, p, d);
  if((onion != NULL) && (onionp != NULL)){
    *onionp = onion;
    return DEFIANT_OK;
  }
  return DEFIANT_MEMORY;
}

int make_pow_onion(size_t dsz, void *d, onion_t *onionp){
  char password[DEFIANT_CLIENT_PASSWORD_LENGTH];
  
  /* generate a random password, then make it simpler */
  srand(time(NULL));
  randomPassword(password, DEFIANT_CLIENT_PASSWORD_LENGTH);
  password[0] =  password[1]  = 'a';
  
  fprintf(stderr, "password = %s\n", password);

  return make_pow_onion_aux(password, dsz, d, onionp);

}

int make_pow_onion_aux(char* password, size_t dsz, void *d, onion_t *onionp){
  int retcode;
  int puzzlc = 0;
  char** puzzlv = NULL;
  int* lengthv = NULL;
  int i;
  onion_t  pow_onion = NULL;
  /* nowhere to put it, don't bother */
  if(onionp == NULL){ return DEFIANT_ARGS; }

  retcode =  make_pow_puzzle_aux(password, d, dsz, &puzzlc, &puzzlv, &lengthv, 0);

  if(retcode == DEFIANT_OK){
    size_t puzzle_size = lengthv[0] + lengthv[1];
    size_t data_size = lengthv[2];
    pow_onion = alloc_onion(POW, puzzle_size, data_size, NULL, puzzlv[2]);
    if(pow_onion != NULL){
      /* add the hash and encrypted secret as the puzzle */
      char *puzzle = ONION_PUZZLE(pow_onion);
      memcpy(puzzle, puzzlv[0], lengthv[0]);
      memcpy(puzzle + lengthv[0], puzzlv[1], lengthv[1]);
    } else {
      retcode = DEFIANT_MEMORY;
    }

    /* time to clean up */
    for(i = 0; i < DEFIANT_CLIENT_PUZZLE_LENGTH; i++){  free(puzzlv[i]); }
    free(puzzlv);
    free(lengthv);
  
  }
  
  /* deliver the goods */
  if(retcode == DEFIANT_OK){
    *onionp = pow_onion;
  }
  
  return DEFIANT_OK;
}


/* easiest way is to make the puzzle */
int check_pow_onion(char* password, onion_t onion, onion_t inside){
  int result;
  size_t puzzle_size = ONION_PUZZLE_SIZE(onion);
  char* puzzle = ONION_PUZZLE(onion);
  char* data = ONION_DATA(onion);
  size_t data_size = ONION_DATA_SIZE(onion);
  char **b64_puzzle = (char **)calloc(DEFIANT_CLIENT_PUZZLE_LENGTH, sizeof(char *));
  if(puzzle == NULL){  return DEFIANT_MEMORY; }
  b64_puzzle[0] = enbase64((uchar*)puzzle, SHA_DIGEST_LENGTH, NULL);
  b64_puzzle[1] = enbase64((uchar*)(puzzle + SHA_DIGEST_LENGTH), puzzle_size - SHA_DIGEST_LENGTH, NULL);
  b64_puzzle[2] = enbase64((uchar*)data, data_size, NULL);
  result = check_puzzle_aux(password, inside, ONION_SIZE(inside), DEFIANT_CLIENT_PUZZLE_LENGTH, b64_puzzle);
  free_puzzle(DEFIANT_CLIENT_PUZZLE_LENGTH, b64_puzzle);
  return result;
}


static char *defiant_captchargv[] = {
  (char *)"java", 
  (char *)"-cp", 
  NULL,
  (char *)"Pinger",
  (char *)"false",
  NULL,
  NULL,
  NULL
};


static int _makeCaptcha(void){
  pid_t childpid = fork();
  if(childpid < 0){
    /* fprintf(stderr, "Forking failed, thats gotta be bad...\n"); */
    return DEFIANT_MEMORY;
  } else if(childpid  == 0){
    /* child  */
    execvp(defiant_captchargv[0], defiant_captchargv);
  } else {
    pid_t mortal;
    /* parent */
    while((mortal = waitpid(childpid, NULL, 0))){
      if(mortal == childpid){
        /* fprintf(stderr, "OK I waited  on: %d\n", mortal); */
        return DEFIANT_OK;
      } else if((mortal == -1) && (errno == EINTR)){  
        continue;
      }
    }
  }
  /* keep the compiler happy  with some dead code */
  return DEFIANT_OK;
}

int makeCaptcha(const char* password, const char* path){
  char* java_cp = getenv("DEFIANT_CLASSPATH");
  if(java_cp == NULL){
    return DEFIANT_MISCONFIGURED;
  } else {
    defiant_captchargv[2] = java_cp;
    defiant_captchargv[5] = (char *)password;
    defiant_captchargv[6] = (char *)path;
    /*
      fprintf(stderr, "%s %s %s %s %s %s %s\n", 
      defiant_captchargv[0], defiant_captchargv[1], defiant_captchargv[2], defiant_captchargv[3], defiant_captchargv[4],
      defiant_captchargv[5], defiant_captchargv[6]);
    */

    return _makeCaptcha();
  }
}


int make_captcha_onion(size_t dsz, void *d, onion_t *onionp){
  char password[DEFIANT_CAPTCHA_PASSWORD_LENGTH];
  randomPasswordEx(password, DEFIANT_CAPTCHA_PASSWORD_LENGTH, 0);
  /* fprintf(stderr, "[%s]\n", password); */
  return make_captcha_onion_aux(password, dsz, d, onionp);
}

/* flick off to leave the images around */
#define UNLINK 1

int make_captcha_onion_aux(char* password, size_t dsz, void *d, onion_t *onionp){
  int retcode, bytesread;
  char cpath[DEFIANT_CAPTCHA_PASSWORD_LENGTH + 10];
  char *bytes = NULL;
  snprintf(cpath, DEFIANT_CAPTCHA_PASSWORD_LENGTH + 10, "/tmp/%s.png", password);
  retcode = makeCaptcha(password, cpath); 
  if(retcode != DEFIANT_OK){ return retcode; }
  retcode = file2bytes(cpath, &bytesread, &bytes);
  if(UNLINK){ unlink(cpath);  }  
  /*  fprintf(stderr, "OK[%d] I read in %d bytes\n", retcode, bytesread); */
  if(retcode != DEFIANT_OK){ 
    return retcode; 
  } else {
    /* now we need to encrypt the inner onion d with the password and then make the onion */
    int cipher_len = 0;
    uchar *cipher = defiant_pwd_encrypt(password, d, dsz, &cipher_len);
    onion_t captcha_onion = alloc_onion(CAPTCHA, bytesread, cipher_len, bytes, cipher);
    *onionp = captcha_onion;
    /* clean up the callocing */
    free(cipher);
    free(bytes);
    return DEFIANT_OK;
  }
}

/* easiest way is to ignore the image and cheat */
int check_captcha_onion(char* password, onion_t onion, onion_t inside){
  char* data = ONION_DATA(onion);
  size_t data_size = ONION_DATA_SIZE(onion);
  int plain_len = 0;
  uchar *plain = defiant_pwd_decrypt(password, (uchar*)data, data_size, &plain_len);
  if(plain_len != (int)ONION_SIZE(inside)){
    return -1;
  } else {
    int retval =  memcmp(plain, inside, plain_len);
    free(plain);
    return retval;
  }
}



int check_signed_onion(FILE* public_key_fp, onion_t onion, onion_t inside){
  int retcode = verify_onion(public_key_fp, onion);
  if(retcode == DEFIANT_OK){
    if(ONION_SIZE(inside) == ONION_DATA_SIZE(onion)){
      return memcmp(ONION_DATA(onion), inside, ONION_DATA_SIZE(onion)) == 0 ? DEFIANT_OK : DEFIANT_DATA;
    }
  }
  return DEFIANT_DATA;
}

char* timestamp(time_t* nowp){
  char* stamp = asctime(localtime(nowp));
  char* cr = strchr(stamp, '\n');
  if(cr){ *cr = '\0'; }
  return stamp;
}

