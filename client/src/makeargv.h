#ifdef __cplusplus
extern "C" {
#endif

  int makeargv(const char *s, const char *delimiters, char ***argvp);

  void freeargv(int argc, char**argv);

  void printargv(FILE* stream, const char* prefix, int argc, char**argv);

  char* fetchv(const char* prefix, int argc, char** argv);


#ifdef __cplusplus
}	/*  extern "C" */

#endif /* __cplusplus */
