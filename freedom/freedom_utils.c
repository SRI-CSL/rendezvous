#include "freedom_utils.h"
#include "cryptlib.h"
#include "onionlib.h"
#include "utils.h"
#include "defiantrequest.h"
#include <ctype.h>

extern module AP_MODULE_DECLARE_DATA freedom_module;

#if VERBOSE
/* would be nice if apr had some simple documented way of getting the pid */
#include <sys/types.h>
#include <unistd.h>
#endif

static int is_rl_stale(freedom_server_config *svr_cfg, request_rec *r){
  char* rlf_path = svr_cfg->rlf_path;
  apr_time_t rlf_mtime = svr_cfg->rlf_mtime;
  apr_time_t current_rlf_mtime = get_mtime(rlf_path, r->pool);

#if VERBOSE  
  RLOG(r, "child[%d]: rlf_path = %s; mtime @ startup = %ld, now = %ld", 
       (int)getpid(), rlf_path, (long)rlf_mtime, (long)current_rlf_mtime); 
#endif
  
  return rlf_mtime !=  current_rlf_mtime;
}

/* N.B. NEED to use the global lock to obtain access to the file, don't want to load it while it is being written. */
/* return val indicates the number of replies reloaded */
int reload_reply_list_file(request_rec *r){
  int retval = 0;
  freedom_server_config *svr_cfg = ap_get_module_config(r->server->module_config, &freedom_module);
  char* rlf_path = svr_cfg->rlf_path;
  if(is_rl_stale(svr_cfg, r)){
    int locked = 0;
    apr_thread_mutex_t *mutex = svr_cfg->rlf_mutex;
    if(mutex != NULL){
      apr_status_t status = apr_thread_mutex_trylock(mutex);
      if(!APR_STATUS_IS_EBUSY(status)){
        locked = 1;
      }
    }
    if(locked){
      apr_array_header_t* rlf_array = onionfile_to_array(r->server, svr_cfg, rlf_path, r->server->process->pool);
      if(rlf_array != NULL){
        /* could retry staleness; but reloading twice is not too troublesome. */
        svr_cfg->rlf_mtime = get_mtime(rlf_path, r->pool);
        svr_cfg->rlf_array = rlf_array;
        retval = rlf_array->nelts;
      }
      apr_thread_mutex_unlock(mutex);
    }
  }
  return retval;
}

/* returns the number of seconds since the server last did its update task      */
int freedom_seconds_since_update(freedom_server_config *svr_cfg, request_rec *r){
  int retval = -1;
  if(svr_cfg != NULL){
    char* rlf_path = svr_cfg->rlf_path;
    apr_time_t then = get_mtime(rlf_path, r->pool);
    apr_time_t now = apr_time_now();
    retval = (int)(((now - then)/1000000));
  }
  return retval;
}

apr_time_t get_mtime(const char* path, apr_pool_t* p){
  apr_finfo_t finfo;
  apr_status_t status;
  if (path == NULL){ return 0; }
  if ((status = apr_stat(&finfo, path, APR_FINFO_MTIME, p)) != 0){ 
    return 0; 
  }
  return finfo.mtime;
}

static int isb64(char c){
  return isalpha(c) || isdigit(c) || (c == '+') || (c == '/') || (c == '=');
}


static char* extract_data(request_rec *r, char* query){
  char* retval = NULL;
  char* data = strstr(query, MOD_FREEDOM_UPDATE_CONTENT);
  int start = strlen(MOD_FREEDOM_UPDATE_CONTENT);
  if(data[start] != '='){ 
    return NULL;
  } else {
    int index = ++start;
    char c = data[index];
    while(isb64(c)){ c = data[++index]; }
    return apr_pstrndup(r->pool, &data[start], index - start);
  }
}

int apr_is_defiant_request(bf_key_pair_t* key_pair, apr_uri_t* urip, char** passwordp){
  if((key_pair == NULL) || (urip == NULL) || (passwordp == NULL)){
    return DEFIANT_ARGS;
  } else {
    return is_defiant_request_aux(key_pair, urip->query, passwordp);
  }
}

