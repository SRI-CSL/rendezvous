#ifndef _FREEDOM_CONFIG_H_
#define _FREEDOM_CONFIG_H_

#include "freedom.h"
#include "defiantbf.h"

typedef struct freedom_server_config {

  /**** book keeping ****/
  int initialized_with_no_issues;
  

  /**** onions *****/

  /* inter process mutex for making sure only one process bothers to do the update */
  apr_global_mutex_t*  server_update_mutex; 

  /* response list file path */
  char* rlf_path;

  /* response list file modification time at server startup */
  apr_time_t rlf_mtime;

  /* rlf array; containing the verified onions loaded from the rlf */
  apr_array_header_t* rlf_array;

  /* local lock to synchronize reloading of rlf_file; reading the file should be protected by the server mutex */
  apr_thread_mutex_t* rlf_mutex;

  /**** ibe *****/

  /* key pair path */
  char* key_pair_path;

  /* key pair */
  bf_key_pair_t* key_pair;

  /**** onion factory *****/
  char *defiance_public_key_path;
  char *tor_hidden_service;
  char *tor_proxy_address;
  long tor_proxy_port;
  int  tor_proxy_protocol;
  
  int update_interval;

  /**** outguess ****/
  
  char *image_library_directory;


} freedom_server_config;


void* freedom_create_server_config(apr_pool_t* pool, server_rec* s);

const char* freedom_server_file_command (cmd_parms* cmd, void* cfg, const char* arg);

const char* freedom_key_pair_file_command (cmd_parms* cmd, void* cfg, const char* arg);

const char* freedom_image_library_command (cmd_parms* cmd, void* cfg, const char* arg);

const char* freedom_defiance_public_key_path_command (cmd_parms* cmd, void* cfg, const char* arg);
const char* freedom_tor_hidden_service_command (cmd_parms* cmd, void* cfg, const char* arg);
const char* freedom_tor_proxy_address_command (cmd_parms* cmd, void* cfg, const char* arg);
const char* freedom_tor_proxy_port_command (cmd_parms* cmd, void* cfg, const char* arg);
const char* freedom_tor_proxy_protocol_command (cmd_parms* cmd, void* cfg, const char* arg);

const char* freedom_update_interval_command (cmd_parms* cmd, void* cfg, const char* arg);

//const char* freedom_set_onions_per_period(cmd_parms* cmd, void* cfg, const char* arg);
//const char* freedom_set_period(cmd_parms* cmd, void* cfg, const char* arg);

/* re-open the server_update_mutex in a child process. */
int freedom_process_init(server_rec* server, freedom_server_config *svr_cfg);

#endif

