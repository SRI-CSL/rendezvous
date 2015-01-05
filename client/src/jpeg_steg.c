#include "jpeg_steg.h"
#include "defianterrors.h"
#include "defiantclient.h"
#include "makeargv.h"

#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <sys/wait.h>

#define KBYTE 1024
#define JPEG_STEG_CLEANUP
#define JPEG_STEG_DEBUG 1
#define JPEG_STEG_LOGFILE "/tmp/jpeg_steg.log"

static int embed_aux(const char* secret, const char* onion, size_t onion_sz, const char* image_path, char** image_bytesp, size_t* image_szp);
static int extract_aux(const char* secret, const char* image_bytes, size_t image_sz,  char** onionp, size_t* onion_szp, char** image_path, char** image_dir);

/* RATPAC request */
int embed(const char* secret, const char* onion, size_t onion_sz, const char* image_path, char** image_bytesp, size_t* image_szp){
  return (secret == NULL) ? DEFIANT_ARGS : embed_aux(secret, onion, onion_sz, image_path, image_bytesp, image_szp);
}

/* RATPAC request */
int extract(const char* secret, const char* image_bytes, size_t image_sz,  char** onionp, size_t* onion_szp){
  return (secret == NULL) ? DEFIANT_ARGS : extract_aux(secret, image_bytes, image_sz,  onionp, onion_szp, NULL, NULL);
}

/* JumpBox variation */
int extract_n_save(const char* secret, const char* image_bytes, size_t image_sz,  char** onionp, size_t* onion_szp, char** image_path, char** image_dir){
  return (secret == NULL) ? DEFIANT_ARGS : extract_aux(secret, image_bytes, image_sz,  onionp, onion_szp, image_path, image_dir);
}

/* cleanup any dodgey characters in the secret -- just in case they sneak in */
static char* cleanse(const char* tainted){
  char *retval = NULL;
  int i = 0, len = 0;
  if(tainted != NULL){ 
    retval = strdup(tainted);
    len = (int)strlen(tainted);
    for(i = 0; i < len; i++){
      if(!isalnum(tainted[i])){
        retval[i] = '_';
      }
    }
  }
  return retval; 
}



/*  wedge/unwedge 

    wedge -data onion image target

    unwedge -outfile target image
*/
static int make_embed_argv(FILE* logger, char **argvp[], const char* secret, const char* datafile, const char* image_path, const char* targetfile){
  int argvindex = 0, argc = 6;
  char **argv = NULL;
  fprintf(logger, "jpeg_steg.c: WEDGING\n");
  if((argvp == NULL) || (datafile == NULL) || (image_path == NULL) || (targetfile == NULL)){
    if(JPEG_STEG_DEBUG){
      //mention secret just to satisfy crazy compile switches
      fprintf(logger, "jpeg_steg.c: bad args for make_embed_argv %s\n", (secret == NULL ? "" : ""));
      fflush(logger);
    }
    return -1;
  }
  argv = calloc(argc, sizeof argv);
  if(argv == NULL){
    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: calloc failed for make_embed_argv\n");
      fflush(logger);
    }
    return -2;
  }
  argv[argvindex++] = strdup("wedge");
  argv[argvindex++] = strdup("-data");
  argv[argvindex++] = strdup(datafile);
  argv[argvindex++] = strdup(image_path);
  argv[argvindex++] = strdup(targetfile);
  argv[argvindex] = NULL;
  *argvp = argv;
  return argc;
}

static int make_extract_argv(FILE* logger, char **argvp[], const char* secret, const char* imagefile, const char* targetfile){
  int argvindex = 0, argc = 5;
  char **argv = NULL;
  if((argvp == NULL) || (imagefile == NULL) || (targetfile == NULL)){
    if(JPEG_STEG_DEBUG){
      //mention secret just to satisfy crazy compile switches
      fprintf(logger, "jpeg_steg.c: bad args for make_extract_argv %s\n", (secret == NULL ? "" : ""));
      fflush(logger);
    }
    return -1;
  }
  argv = calloc(argc, sizeof argv);
  if(argv == NULL){
    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: calloc failed for make_extract_argv\n");
      fflush(logger);
    }
    return -2;
  }
  argv[argvindex++] = strdup("unwedge");
  argv[argvindex++] = strdup("-outfile");
  argv[argvindex++] = strdup(targetfile);
  argv[argvindex++] = strdup(imagefile);
  argv[argvindex] = NULL;
  *argvp = argv;
  return argc;
}



static void free_argv(int argc, char *argv[]) {
  int i;
  for (i = 0; i < argc; i++) {
    free(argv[i]);
  }
  free(argv);
}

static void log_argv(FILE* logger, int argc, char *argv[]) {
  int i;
  for (i = 0; i < argc; i++) {
    fprintf(logger, "\targv[%d] = %s\n", i, argv[i]);
  }
  fflush(logger);
}

static int launch(FILE* logger, char *argv[]){
  pid_t childpid;
  int status = 0;
  childpid = fork();
  if(childpid == -1){
    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: fork failed in launch\n");
      fflush(logger);
    }
    return -1;
  } else if(childpid == 0){
    int retcode = execvp(argv[0], argv);
    if(retcode < 0){
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: execvp failed: %s\n", strerror(errno));
        fflush(logger);
      }
    }
  } else {
    while(waitpid(childpid, &status, WUNTRACED) < 0){
      if(errno != EINTR){ break; }
    }
    if(WIFEXITED(status) && !WEXITSTATUS(status)){
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: waited on happy camper %d with status %d\n", childpid, status);
        fflush(logger);
      }
      return 0;
    } else {
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: waited on UNHAPPY child %d with status %d\n", childpid, status);
        fflush(logger);
      }
    }
  }
  return status;
}


#define TMP_TEMPLATE "jpeg_steg_embedXXXXXX"

int extract_aux(const char* secret, const char* image_bytes, size_t image_sz,  char** onionp, size_t* onion_szp, char** image_path, char** image_dir){
  int retval = DEFIANT_ARGS;
  FILE* logger = stderr;
  if(JPEG_STEG_DEBUG){
    logger = fopen(JPEG_STEG_LOGFILE, "a+");
    if(logger == NULL){ logger = stderr; }
  }
  if((image_bytes == NULL) || (image_sz == 0) || (onionp == NULL) || (onion_szp == NULL)){
    return retval;
  } else {
    char* onion = NULL;
    int rmdircode;
    int onion_sz = 0;
    char* datadir;
    char datatemplate[MAX_PATH+64], tmpdir[MAX_PATH];
    char imagefile[KBYTE], targetfile[KBYTE];
    char* cleansecret = cleanse(secret);

    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: extract_aux()\n");
      fflush(logger);
    }

      

    memset(tmpdir, 0, sizeof tmpdir);
#ifndef _WIN32
    snprintf(tmpdir, sizeof tmpdir, "/tmp/");
#else
    GetTempPathA(sizeof tmpdir, tmpdir);
#endif

    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: Temporary Path: %s\n", tmpdir);
      fflush(logger);
    }
    

    snprintf(datatemplate, sizeof datatemplate, "%s%s", tmpdir, TMP_TEMPLATE);
    datadir = mkdtemp(datatemplate);
    if (datadir == NULL) {
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: Could not create a temporary directory\n");
        fflush(logger);
      }
      retval = DEFIANT_DATA;
      goto cleanup;
    }

    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: Temporary Dir: %s\n", datadir);
      fflush(logger);
    }


    snprintf(imagefile, sizeof imagefile, "%s" PATH_SEPARATOR "image.jpg", datadir);
    snprintf(targetfile, sizeof targetfile, "%s" PATH_SEPARATOR "onion.bin", datadir);


    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: storing image %s of %" PRIsizet " bytes\n", imagefile, image_sz);
      fflush(logger);
    }

    if(JPEG_STEG_DEBUG){
      retval = bytes2file_logging(logger, imagefile, image_sz, image_bytes);
    } else {
      retval = bytes2file(imagefile, image_sz, image_bytes);
    }

    if(retval != DEFIANT_OK){ 
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: bytes2file(%s) returned %d\n", imagefile, retval);
        fflush(logger);
      }
      goto cleanup; 
    }

    /* uses fork-exec */
    char**argv = NULL;
    int argc = make_extract_argv(logger, &argv, cleansecret, imagefile, targetfile);
    if(argc > 0){
      if(JPEG_STEG_DEBUG){ log_argv(logger, argc, argv); }
      retval = launch(logger, argv);
      free_argv(argc, argv);
    } else {
      retval = DEFIANT_DATA;
    }
    
    if(retval != 0){
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: spawing returned %d\n", retval);
        fflush(logger);
      }
      retval = DEFIANT_DATA;
      goto cleanup;
    } else {

      if(JPEG_STEG_DEBUG){
        retval = file2bytes_logging(logger, targetfile, &onion_sz, &onion);
      } else {
        retval = file2bytes(targetfile, &onion_sz, &onion);
      }
      


      if(retval != DEFIANT_OK){ 
        if(JPEG_STEG_DEBUG){
          fprintf(logger, "jpeg_steg.c: file2bytes(%s) returned %d\n", targetfile, retval);
          fflush(logger);
        }
        goto cleanup;
      }
      *onion_szp = onion_sz;
      *onionp = onion;
      retval = DEFIANT_OK;
    }

  cleanup:
    free(cleansecret);
    if((image_path != NULL) && (image_dir != NULL)){
      //called from jumpbox, need to save the image so the plugin can display it.
      *image_path = strdup(imagefile);
      *image_dir = strdup(datadir);
#ifdef JPEG_STEG_CLEANUP
      unlink(targetfile);
#endif
    } else {
      unlink(targetfile);
      unlink(imagefile);
      rmdircode = rmdir(datadir);
      if(rmdircode != 0){
        if(JPEG_STEG_DEBUG){
          fprintf(logger, "jpeg_steg.c: rmdir(%s) returned %d with errno: %d\n", datadir, rmdircode, errno);
          fflush(logger);
        }
      }
    }
    if(logger != stderr){ fclose(logger); }

    return  retval;
  }
}


int embed_aux(const char* secret, const char* onion, size_t onion_sz, const char* image_path, char** image_bytesp, size_t* image_szp){
  int retval = DEFIANT_ARGS;
  FILE* logger = stderr;
  if(JPEG_STEG_DEBUG){
    logger = fopen(JPEG_STEG_LOGFILE, "a+");
    if(logger == NULL){ logger = stderr; }
  }
  if((onion == NULL) || (onion_sz == 0) || (image_path == NULL) || (image_bytesp == NULL) || (image_szp == NULL)){
    return retval;
  } else {
    char* image_bytes = NULL;
#ifdef JPEG_STEG_CLEANUP
    int rmdircode;
#endif
    int image_sz = 0;
    char* datadir;
    char datatemplate[MAX_PATH+64], tmpdir[MAX_PATH];
    char datafile[KBYTE], targetfile[KBYTE];
    char* cleansecret = cleanse(secret);

    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: embed_aux()\n");
      fflush(logger);
    }

    memset(tmpdir, 0, sizeof tmpdir);
#ifndef _WIN32
    snprintf(tmpdir, sizeof tmpdir, "/tmp/");
#else
    GetTempPathA(sizeof tmpdir, tmpdir);
#endif

    if(JPEG_STEG_DEBUG)fprintf(logger, "jpeg_steg.c: Temporary Path: %s\n", tmpdir);

    snprintf(datatemplate, sizeof datatemplate, "%s%s", tmpdir, TMP_TEMPLATE);
    datadir = mkdtemp(datatemplate);
    if (datadir == NULL) {
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: Could not create a temporary directory\n");
        fflush(logger);
      }
      retval = DEFIANT_DATA;
      goto cleanup;
    }

    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: Temporary Dir: %s\n", datadir);
      fflush(logger);
    }

    snprintf(datafile, sizeof datafile, "%s" PATH_SEPARATOR "onion.bin", datadir);
    snprintf(targetfile, sizeof targetfile, "%s" PATH_SEPARATOR "target.jpg", datadir);


    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: storing image %s of %" PRIsizet " bytes\n", datafile, onion_sz);
      fflush(logger);
    }
    retval = bytes2file(datafile, onion_sz, onion);

    if(retval != DEFIANT_OK){ 
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: bytes2file(%s) returned %d\n", datafile, retval);
        fflush(logger);
      }
      goto cleanup;
    }

    /* uses fork-exec */
    char**argv = NULL;
    int argc = make_embed_argv(logger, &argv, cleansecret, datafile, image_path, targetfile);
    if(argc > 0){
      if(JPEG_STEG_DEBUG){ log_argv(logger, argc, argv); }
      retval = launch(logger, argv);
      free_argv(argc, argv);
    } else {
      retval = DEFIANT_DATA;
    }
    
    if(retval != 0){
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: launch returned %d\n", retval);
        printargv(logger, "jpeg_steg.c: launch", argc, argv);
        fflush(logger);
      }
      retval = DEFIANT_DATA;
      goto cleanup;
    } else {
      retval = file2bytes(targetfile, &image_sz, &image_bytes);
      if(retval != DEFIANT_OK){ 
        if(JPEG_STEG_DEBUG){
          fprintf(logger, "jpeg_steg.c: file2bytes(%s) returned %d\n", targetfile, retval);
          fflush(logger);
        }
        goto cleanup;
      } else {
        *image_bytesp = image_bytes;
        *image_szp = image_sz;
        retval = DEFIANT_OK;
      }
    }
    
  cleanup:
    free(cleansecret);
#ifdef JPEG_STEG_CLEANUP
    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: Cleaning up tmp dir %s\n", datadir);
      fflush(logger);
    }
    unlink(datafile);
    unlink(targetfile);
    rmdircode = rmdir(datadir);
    if(rmdircode != 0){
      if(JPEG_STEG_DEBUG){
        fprintf(logger, "jpeg_steg.c: rmdir(%s) returned %d with errno: %d\n", datadir, rmdircode, errno);
        fflush(logger);
      }
    }
#else
    if(JPEG_STEG_DEBUG){
      fprintf(logger, "jpeg_steg.c: Not cleaning up tmp dir %s\n", datadir);
      fflush(logger);
    }
#endif
  }
  if(logger != stderr){ fclose(logger); }
  return retval;
}


static int seeded = 0;
static char buff[1024];



char* random_file(const char* directory){
  if(directory != NULL){
    struct dirent *direntp;
    DIR *dirp;
    if((dirp = opendir(directory)) != NULL){
      //determine the number of child files; "." and ".." not included
      int count = 0;  
      while((direntp = readdir(dirp)) != NULL){
        if((direntp != NULL) && strcmp(".", direntp->d_name) && strcmp("..", direntp->d_name)){
          count++;
        }
      }
      if(count == 0){
        return NULL;
      } else {
        rewinddir(dirp);
        if(!seeded){
          srand(time(NULL));
          seeded = 1;
        }
        int rint = rand();
        float ratio = 1;
        ratio  = (ratio * rint) / RAND_MAX;
        int i = 0, rindx = (int)(ratio * count);
        while(i <= rindx){
          direntp =  readdir(dirp);
          if((direntp != NULL) && strcmp(".", direntp->d_name) && strcmp("..", direntp->d_name)){
            i++;
          }
        }
        buff[0] = '\0';
        if(direntp != NULL){
          snprintf(buff, 1024, "%s/%s", directory, direntp->d_name);
        }
        closedir(dirp);
        return buff;
      }
    }
  }
  return NULL;
}




