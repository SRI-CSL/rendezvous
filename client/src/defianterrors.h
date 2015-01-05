#ifndef _DEFIANTERRORS_H
#define _DEFIANTERRORS_H

/* very course grained error codes */
enum defiant_codes { 
  DEFIANT_OK, 
  DEFIANT_MEMORY, 
  DEFIANT_FILE, 
  DEFIANT_EOF, 
  DEFIANT_CRYPTO, 
  DEFIANT_ARGS, 
  DEFIANT_DATA, 
  DEFIANT_INTERNET, 
  DEFIANT_UNSUPPORTED,
  DEFIANT_MISCONFIGURED
};

const char *defiant_strerror(int error);

#endif /* _DEFIANTERRORS_H */

