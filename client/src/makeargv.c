/* 
   makeargv written by ian a. mason @ une 1/8/2002
   the argv and each argv[i] can be freed after use.
   no sharing with the original string.
*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "makeargv.h"

#define MAKEARGV_DEBUG 0


void freeargv(int argc, char** argv){
  if(argc > 0){
    int i;
    for(i = 0; i < argc; i++){ free(argv[i]); }
  }
  free(argv);
}

#ifdef _WINDOWS
#pragma warning(push)
#pragma warning(disable : 4996)
#endif

static int makeargvaux(const char *s, int slen, const char *delimiters, char ***argvp);
static int makeargvaux(const char *s, int slen, const char *delimiters, char ***argvp){
  int argc = 0;
  if(slen == 0){
    *argvp = NULL;
    return 0;
  } else {
    int start = 0, end = 0;
    char **argv = (char **)calloc(slen, sizeof(char *));
    if(argv == NULL) return -1;
    if(MAKEARGV_DEBUG)
      fprintf(stderr, 
              "Entering loop &s[start] = \"%s\"\n",
              &s[start]);
    while(s[start] != '\0'){
      if(MAKEARGV_DEBUG)fprintf(stderr, "Looping\n");
      /* remove all starting delimiters  */
      while((s[start] != '\0') &&
            (strchr(delimiters, s[start]) != NULL))
        start++;
      if(MAKEARGV_DEBUG)fprintf(stderr, "Delimiters removed &s[start] = \"%s\"\n", &s[start]);
      if(s[start] == '\0'){
        if(MAKEARGV_DEBUG)fprintf(stderr, "End of string\n");
        if(argc == 0){
          free(argv);
          *argvp = NULL;
          return argc;
        } else {
          argv[argc] = NULL;
          *argvp = argv;
          return argc;
        }
      } /* s[start] != '\0' */
      end = start;
      /* find the end of the current token */
      while((s[end] != '\0') &&
            strchr(delimiters, s[end]) == NULL)
        end++;
      if(MAKEARGV_DEBUG)fprintf(stderr, "Token end found: &s[end] = \"%s\"\n", &s[end]);
      argv[argc] = (char *)calloc((end - start) + 1, sizeof(char));
      if(argv[argc] == NULL){
        free(argv);
        return -1;
      }
      strncpy(argv[argc], (char *)&s[start], end - start);
      argv[argc][end - start] = '\0';
      argc++;
      start = end;
    }
    argv[argc] = NULL;
    *argvp = argv;
    return argc;
  }
}

#ifdef _WINDOWS
#pragma warning(pop) 
#endif

int makeargv(const char *s, const char *delimiters, char ***argvp){
  if(argvp == NULL)    
    return -1;
  if(s == NULL){
    *argvp = NULL;
    return 0;
  } else {
    int slen = (int)strlen(s);
    return makeargvaux(s, slen, delimiters, argvp);
  }
}


void printargv(FILE* stream, const char* prefix, int argc, char** argv){
  int i;
  for(i = 0; i < argc; i++){
    fprintf(stream, "%s[%d] = %s\n", prefix, i, argv[i]);
  }
}

char* fetchv(const char* prefix, int argc, char** argv){
  int i, preflen = strlen(prefix);
  char* retval = NULL;
  for(i = 0; i < argc; i++){
    if(strncmp(prefix, argv[i], preflen) == 0){
      char *value = &(argv[i][preflen]);
      int len = strlen(value);
      if(len > 0){
        retval = (char *)calloc(len + 1, sizeof(char));
        if(retval != NULL){
          strncpy(retval, value, len);
          retval[len] = '\0';
        }
      }
    }
  }
  return retval;
}
