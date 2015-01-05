#include "freedom.h"
#include "freedom_config.h"
#include "freedom_utils.h"
#include "onionlib.h"
#include "defianterrors.h"

extern module AP_MODULE_DECLARE_DATA freedom_module;

static int server_update_mutex_initialized = 0;

const command_rec freedom_commands[] = {
  AP_INIT_TAKE1("FreedomServerFile", freedom_server_file_command, NULL, RSRC_CONF, "A file containing the responses"),
  AP_INIT_TAKE1("FreedomKeyPairFile", freedom_key_pair_file_command, NULL, RSRC_CONF, "A file containing the IBE key pair for this server"),
  AP_INIT_TAKE1("FreedomImageDirectory", freedom_image_library_command, NULL, RSRC_CONF, "A directory of images for outguess"),
  AP_INIT_TAKE1("FreedomDefiancePublicKeyPath", freedom_defiance_public_key_path_command, NULL, RSRC_CONF, "Path to DEFIANCE public key (for verifying onions)"),
  AP_INIT_TAKE1("FreedomTorHiddenService", freedom_tor_hidden_service_command, NULL, RSRC_CONF, "URL for the Onion Factory (a tor hidden service)"),
  AP_INIT_TAKE1("FreedomTorProxyAddress", freedom_tor_proxy_address_command, NULL, RSRC_CONF, "URL for the local tor instance (e.g. \"127.0.0.1\")"),
  AP_INIT_TAKE1("FreedomTorProxyPort", freedom_tor_proxy_port_command, NULL, RSRC_CONF, "Port for the local tor instance (e.g. 9060)"),
  AP_INIT_TAKE1("FreedomTorProxyProtocol", freedom_tor_proxy_protocol_command, NULL, RSRC_CONF, "Curl code for the tor proxy protocol (e.g. 6 for socks4a)"),
  AP_INIT_TAKE1("FreedomUpdateInterval", freedom_update_interval_command, NULL, RSRC_CONF, "Interval in seconds before an update gets triggered"),
  { NULL }};

#define FREEDOM_EXISTS     1
#define FREEDOM_ISREG      2
#define FREEDOM_ISDIR      4
#define FREEDOM_ISNONZERO  8

#define FREEDOM_FILE_CHECK (FREEDOM_EXISTS|FREEDOM_ISREG|FREEDOM_ISNONZERO)
#define FREEDOM_DIR_CHECK  (FREEDOM_EXISTS|FREEDOM_ISDIR)

static int path_check(int flags, const char *path, apr_pool_t *p){
  apr_finfo_t finfo;
  if (path == NULL){ return 0; }
  if (flags & FREEDOM_EXISTS && apr_stat(&finfo, path, APR_FINFO_TYPE|APR_FINFO_SIZE, p) != 0)
    return 0;
  if (flags & FREEDOM_ISREG && finfo.filetype != APR_REG)
    return 0;
  if (flags & FREEDOM_ISDIR && finfo.filetype != APR_DIR)
    return 0;
  if (flags & FREEDOM_ISNONZERO && finfo.size <= 0)
    return 0;
  return 1;
}

const char* freedom_defiance_public_key_path_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  int isOK;
  if(arg != NULL){
    const char *filepath = ap_server_root_relative(cmd->pool, arg);
    if (!filepath) {
      SERR(cmd->server, "freedom_defiance_public_key_path_command: got invalid file path %s from httpd.conf",  arg);
      svr_cfg->initialized_with_no_issues = 0;
      return NULL;
    } else {
      SLOG(cmd->server, "freedom_defiance_public_key_path_command: got %s from httpd.conf",  arg);
      isOK = path_check(FREEDOM_FILE_CHECK, filepath, cmd->pool);
      if(!isOK){
        SERR(cmd->server,  "Couldn't check path for defiance public key at %s because %s, go figure... \n", filepath, strerror(errno));
        svr_cfg->initialized_with_no_issues = 0;
        return NULL;
      } else {
        svr_cfg->defiance_public_key_path = apr_pstrdup(cmd->pool, filepath);
        SLOG(cmd->server, "freedom_defiance_public_key_path_command: setting cfg->defiance_public_key_path to:  %s", svr_cfg->defiance_public_key_path);
        SLOG(cmd->server, "Check path for defiance public key at %s OK",  filepath);
      }
    }
  } else {
    svr_cfg->initialized_with_no_issues = 0;
  }
  return NULL;
}

const char* freedom_tor_hidden_service_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  SLOG(cmd->server, "freedom_tor_hidden_service_command: got %s from httpd.conf",  arg);
  svr_cfg->tor_hidden_service = apr_pstrdup(cmd->pool, arg);
  if(svr_cfg->tor_hidden_service == NULL){
    svr_cfg->initialized_with_no_issues = 0;
  }
  return NULL;
}

const char* freedom_tor_proxy_address_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  SLOG(cmd->server, "freedom_tor_proxy_address_command: got %s from httpd.conf",  arg);
  svr_cfg->tor_proxy_address =  apr_pstrdup(cmd->pool, arg);
  if(svr_cfg->tor_proxy_address == NULL){
    svr_cfg->initialized_with_no_issues = 0;
  }
  return NULL;
}

const char* freedom_tor_proxy_port_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  SLOG(cmd->server, "freedom_tor_proxy_port_command: got %s from httpd.conf",  arg);
  svr_cfg->tor_proxy_port = atol(arg);
  if(svr_cfg->tor_proxy_port <= 0){
    svr_cfg->initialized_with_no_issues = 0;
  }
  return NULL;
}

const char* freedom_tor_proxy_protocol_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  SLOG(cmd->server, "freedom_tor_proxy_protocol_command: got %s from httpd.conf",  arg);
  svr_cfg->tor_proxy_protocol = atoi(arg);
  if(svr_cfg->tor_proxy_protocol <= 0){
    svr_cfg->initialized_with_no_issues = 0;
  }
 return NULL;
}

const char* freedom_update_interval_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  SLOG(cmd->server, "freedom_update_interval_command: got %s from httpd.conf",  arg);
  svr_cfg->update_interval = atoi(arg);
  if(svr_cfg->update_interval <= 0){
    svr_cfg->initialized_with_no_issues = 0;
  }
 return NULL;
}


const char* freedom_key_pair_file_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  SLOG(cmd->server, "freedom_key_pair_file_command: got %s from httpd.conf",  arg);
  if(arg != NULL){
    const char *filepath = ap_server_root_relative(cmd->pool, arg);
    if (!filepath) {
      SERR(cmd->server, "freedom_key_pair_file_command: got invalid file path %s from httpd.conf",  arg);
    } else {
      int isOK = path_check(FREEDOM_FILE_CHECK, filepath, cmd->pool);
      if(isOK){
        bf_key_pair_t* key_pair = NULL;
        FILE *fp = fopen(filepath, "rb");
        if(fp == NULL){
          SERR(cmd->server,  "Couldn't open key pair file, %s, go figure... \n", strerror(errno));
          svr_cfg->initialized_with_no_issues = 0;
          return NULL;
        } else {
          int errcode = bf_read_key_pair(fp, &key_pair);
          if(errcode != DEFIANT_OK){
            SERR(cmd->server, "Couldn't load key pair from %s, errcode = %d, go figure... \n", filepath, errcode);
            fclose(fp);
            svr_cfg->initialized_with_no_issues = 0;
            return NULL;
          }
          svr_cfg->key_pair_path = apr_pstrdup(cmd->pool, filepath);
          svr_cfg->key_pair = key_pair;
          fclose(fp);
        }
      } else {
        svr_cfg->initialized_with_no_issues = 0;
        SERR(cmd->server, "freedom_key_pair_file_command: file path %s missing or empty",  filepath);
      }
    }
  }
  return NULL;
}

const char* freedom_server_file_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  SLOG(cmd->server, "freedom_server_file_command: got %s from httpd.conf",  arg);
  if(arg != NULL){
    const char *filepath = ap_server_root_relative(cmd->pool, arg);
    if (!filepath) {
      SERR(cmd->server, "freedom_server_file_command: got invalid file path %s from httpd.conf",  arg);
      svr_cfg->initialized_with_no_issues = 0;
    } else {
      int isOK = path_check(FREEDOM_FILE_CHECK, filepath, cmd->pool);
      //it might not exists yet; so be patient, but remember it
      svr_cfg->rlf_path  = apr_pstrdup(cmd->pool, filepath);
      if(isOK){
        svr_cfg->rlf_mtime = get_mtime(filepath, cmd->pool);
        svr_cfg->rlf_array = onionfile_to_array(cmd->server, svr_cfg, filepath, cmd->pool);
        SLOG(cmd->server, "freedom_server_file_command: %s's mtime = %" PRIu64,  svr_cfg->rlf_path, svr_cfg->rlf_mtime);
      } else {
        //no onions not a problem ...
        SLOG(cmd->server, "freedom_server_file_command: file path %s missing or empty",  filepath);
      }
    }
  }
  return NULL;
}


const char* freedom_image_library_command (cmd_parms* cmd, void* cfg, const char* arg){
  freedom_server_config *svr_cfg = ap_get_module_config(cmd->server->module_config, &freedom_module);
  SLOG(cmd->server, "freedom_image_library_command: got %s from httpd.conf",  arg);
  if(arg != NULL){
    const char *dirpath = ap_server_root_relative(cmd->pool, arg);
    if (!dirpath) {
      SERR(cmd->server, "freedom_image_library_command: got invalid directory path %s from httpd.conf",  arg);
      svr_cfg->initialized_with_no_issues = 0;
    } else {
      int isOK = path_check(FREEDOM_DIR_CHECK, dirpath, cmd->pool);
      if(isOK){
        svr_cfg->image_library_directory  = apr_pstrdup(cmd->pool, dirpath);
        SLOG(cmd->server, "freedom_image_library_command: directory OK -- %s",  svr_cfg->image_library_directory);
      } else {
        //no images, not a problem ...
        SLOG(cmd->server, "freedom_image_library_command: file path %s missing or empty",  dirpath);
      }
    }
  }
  return NULL;
}


void* freedom_create_server_config(apr_pool_t* pool, server_rec* s){
  freedom_server_config* svr_cfg = apr_pcalloc(pool, sizeof(freedom_server_config));
  apr_status_t status;
  /* this gets toggled if there is a problem */
  svr_cfg->initialized_with_no_issues = 1;


  status = apr_thread_mutex_create (&(svr_cfg->rlf_mutex), APR_THREAD_MUTEX_UNNESTED, pool);
  if(status != APR_SUCCESS){
    char errbuf[256];
    apr_strerror(status, errbuf, sizeof(errbuf));
    SERR(s, "apr_thread_mutex_create: %s", errbuf);
    svr_cfg->rlf_mutex = NULL;
  }
  svr_cfg->server_update_mutex = NULL;
  status = apr_global_mutex_create(&(svr_cfg->server_update_mutex), "freedom_file_lock", APR_LOCK_DEFAULT, pool);
  if(status != APR_SUCCESS){
    char errbuf[256];
    apr_strerror(status, errbuf, sizeof(errbuf));
    SERR(s, "apr_global_mutex_create %s", errbuf);
    svr_cfg->server_update_mutex = NULL;
    svr_cfg->initialized_with_no_issues = 0;
  } else {
    server_update_mutex_initialized = 1;
  }
  
  svr_cfg->rlf_array = NULL;
  svr_cfg->rlf_path = NULL;
  svr_cfg->rlf_mtime = 0;

  svr_cfg->key_pair_path = NULL;
  svr_cfg->key_pair = NULL;

  svr_cfg->defiance_public_key_path = NULL;
  svr_cfg->tor_hidden_service = NULL;
  svr_cfg->tor_proxy_address = NULL;
  svr_cfg->tor_proxy_port = -1;
  svr_cfg->tor_proxy_protocol = -1;

  svr_cfg->update_interval = 24 * 60 * 60;

  svr_cfg->image_library_directory = NULL;

  return svr_cfg;
}


int freedom_process_init(server_rec* server, freedom_server_config *svr_cfg){
  apr_status_t status = APR_SUCCESS;
  apr_thread_mutex_t *mutex = svr_cfg->rlf_mutex;
  int locked = 0;
  SLOG(server, "freedom_process_init: %d", server_update_mutex_initialized); 
  if(mutex != NULL){
    apr_status_t status = apr_thread_mutex_trylock(mutex);
    if(!APR_STATUS_IS_EBUSY(status)){
      locked = 1;
    }
  }
  if(locked){
    if(!server_update_mutex_initialized){
      status = apr_global_mutex_child_init(&(svr_cfg->server_update_mutex), "freedom_file_lock", server->process->pool);
      if(status != APR_SUCCESS){
        char errbuf[256];
        apr_strerror(status, errbuf, sizeof(errbuf));
        SERR(server, "apr_global_mutex_child_init %s", errbuf);
      }
      server_update_mutex_initialized = 1;
    }
    apr_thread_mutex_unlock(mutex);
  }
  return status;
}

