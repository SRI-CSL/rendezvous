#include "defianterrors.h"



const char *defiant_strerror(int error){
  switch(error){
  case DEFIANT_OK:            return "No Error";
  case DEFIANT_MEMORY:        return "Out of Memory";
  case DEFIANT_FILE:          return "File I/O Error";
  case DEFIANT_EOF:           return "Unexpected EOF";
  case DEFIANT_CRYPTO:        return "Cryptographic Error";
  case DEFIANT_ARGS:          return "Illegal Arguments";
  case DEFIANT_DATA:          return "Bad Data";
  case DEFIANT_INTERNET:      return "Internet Error";
  case DEFIANT_UNSUPPORTED:   return "Unsupported Operation";
  case DEFIANT_MISCONFIGURED: return "Misconfigured (missing jar?)";
  default:                    return "Unknown Error";
  }
}

