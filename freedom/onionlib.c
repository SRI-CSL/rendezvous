#include "onionlib.h"

#include "onion.h"
#include "defiantconstants.h"
#include "defiantclient.h"

#include "freedom_config.h"

/* for apr_fetch_onions */
#include "utils.h"
#include <curl/curl.h>

extern module AP_MODULE_DECLARE_DATA freedom_module;

/* Avoid pointer-math-alignment issues, use memcpy() */
static uint32_t onioncolcount(onion_t onion_in);
uint32_t onioncolcount(onion_t onion_in) {
  uint32_t count;

  memcpy(&count, ONION_PUZZLE(onion_in), sizeof count);

  /* Onions are stored in network byte order */
  return ntohl(count);
}

int apr_peel_collection_onion(onion_t onion_in, int* onioncp, onion_t** onionvp){
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

static onion_t apr_alloc_onion(int type, size_t psz, size_t dsz, void *p, void *d, apr_pool_t* pool){
  size_t osz = sizeof(onion_header_t) + psz + dsz;
  onion_t o = (onion_t)apr_pcalloc(pool, osz);
  if(o == NULL){ 
    return NULL; 
  } else {
    onion_header_t *oh = (onion_header_t *)o;
    char *buff = (char*)o;
    char *pbuff = buff + sizeof(onion_header_t);
    char *dbuff = pbuff + psz;
    assert(sizeof onion_magic == sizeof oh->magic);
    memcpy(oh->magic, onion_magic, sizeof onion_magic);
    assert(ONION_IS_ONION(oh));
    oh->onion_type = htons(type);	/* 16bit */
    oh->puzzle_size = htonl(psz);	/* 32bit */
    oh->data_size = htonl(dsz);		/* 32bit */
    if(p != NULL){ memcpy(pbuff, p, psz); }
    if(d != NULL){ memcpy(dbuff, d, dsz); }
    return o;
  }
}

static apr_status_t stream2onion(apr_file_t* stream, onion_t *onionp, apr_pool_t* pool){
  onion_header_t header;
  apr_size_t bytesread = sizeof(header);
  apr_status_t status = apr_file_read(stream, &header, &bytesread);
  if((status != APR_SUCCESS) ||  (bytesread != sizeof(header))){
    return APR_EOF;
  } else {
    int onion_type = ONION_TYPE(&header);
    size_t psz = ONION_PUZZLE_SIZE(&header);
    size_t dsz = ONION_DATA_SIZE(&header);
    onion_t onion = apr_alloc_onion(onion_type, psz, dsz, NULL, NULL, pool);
    char *buff = (char*)onion;
    char *pbuff = buff + sizeof(onion_header_t);
    apr_size_t pbuffsz = psz;
    char *dbuff = pbuff + psz;
    apr_size_t dbuffsz = dsz;
    /* read the puzzle */
    status = apr_file_read(stream, pbuff, &pbuffsz);
    if((status != APR_SUCCESS) ||  (pbuffsz != psz)){  return APR_EOF;  }
    /* read the data  */
    status = apr_file_read(stream, dbuff, &dbuffsz);
    if((status != APR_SUCCESS) ||  (dbuffsz != dsz)){  return APR_EOF;  }
    *onionp = onion;
    return APR_SUCCESS;
  }
}


static int apr_verify(FILE* defiant_public_key_fp, onion_t onion){
  if((onion == NULL) || (ONION_TYPE(onion) != SIGNED)){ 
    return FALSE;
  } else {
    int retcode = defiant_verify(defiant_public_key_fp, ONION_DATA(onion),  ONION_DATA_SIZE(onion), (uchar *)ONION_PUZZLE(onion), ONION_PUZZLE_SIZE(onion));
    return (retcode == DEFIANT_OK) ? TRUE : FALSE;
  }
}

static apr_array_header_t* _onionfile_to_array(freedom_server_config *svr_cfg, server_rec* s, const char* path, apr_pool_t* pool);

/* synchronizes access to the RLF */
apr_array_header_t* onionfile_to_array(server_rec* server, freedom_server_config *svr_cfg, const char* path, apr_pool_t* pool){
  apr_array_header_t* retval = NULL;
  apr_status_t status = apr_global_mutex_trylock(svr_cfg->server_update_mutex);
  if(APR_STATUS_IS_EBUSY(status)){
    SLOG(server, "freedom_update_task global lock BUSY %d!", status);
  } else {
    retval = _onionfile_to_array(svr_cfg, server, path, pool);
    apr_global_mutex_unlock(svr_cfg->server_update_mutex);
  }
  return retval;
}

/* actually does the accessing */
apr_array_header_t* _onionfile_to_array(freedom_server_config *svr_cfg, server_rec* s, const char* path, apr_pool_t* pool){
  apr_array_header_t* retval = NULL;
  apr_file_t* stream = NULL;
  apr_status_t status = apr_file_open(&stream, path, APR_READ | APR_BINARY, APR_OS_DEFAULT, pool);

  if(status == APR_SUCCESS){
    onion_t onion = NULL;
    const char *filepath = svr_cfg->defiance_public_key_path;
    FILE* defiant_public_key_fp = fopen(filepath, "r");
    if(defiant_public_key_fp == NULL){
      SERR(s, "onionfile_to_array: Couldn't open public key at %s because %s!",  filepath, strerror(errno));
      return retval;
    } else {
      SLOG(s, "onionfile_to_array:  read public key at %s",  filepath);
    }
    retval = apr_array_make(pool, MOD_FREEDOM_RESPONSE_POOL_SIZE, sizeof(onion_t));
    while(stream2onion(stream, &onion, pool) != APR_EOF){
      if(onion != NULL){
        if(apr_verify(defiant_public_key_fp, onion)){
          onion_t* onionp = (onion_t*)apr_array_push(retval);
          *onionp = onion;
          SLOG(s, "onionfile_to_array: read verified onion of size %" PRIu64, ONION_SIZE(onion));
        } else {
          SLOG(s, "onionfile_to_array: read skipping UNVERIFIED onion of size %" PRIu64, ONION_SIZE(onion));
          onion = NULL;
        }
      }
    }
    fclose(defiant_public_key_fp);
    apr_file_close(stream);
  } else {
    char errbuf[256];
    apr_strerror(status, errbuf, sizeof(errbuf));
    SERR(s, "onionfile_to_array: Couldn't open %s %s!", path, errbuf);
  }
  return retval;
}

static apr_status_t onion2stream(server_rec* s, onion_t onion, apr_file_t* stream){
  apr_size_t bytes = ONION_SIZE(onion);
  apr_status_t status = apr_file_write(stream, onion, &bytes);
  if(bytes != ONION_SIZE(onion)){
    SERR(s, "onion_to_stream: apr_file_write ONLY wrote %" PRIu64 " of %" PRIu64 " bytes!", bytes, ONION_SIZE(onion));
  }
  return status;
}

onion_t apr_fetch_onions(char *cookie, server_rec* s, FILE* public_key_fp, char* onion_url, char* tor_proxy, long tor_proxy_port, int tor_proxy_protocol){
  onion_t retval = NULL;
  CURL* curlobj;
  curl_global_init(CURL_GLOBAL_ALL);
  curlobj = curl_easy_init();
  if(curlobj != NULL){
    CURLcode res, resl, rest;
    response resp = {NULL, 0};
    curl_easy_setopt(curlobj, CURLOPT_TIMEOUT, DEFIANT_CURL_TIMEOUT); 
    curl_easy_setopt(curlobj, CURLOPT_CONNECTTIMEOUT, DEFIANT_CURL_TIMEOUT); 
    //only use tor if the puppy is configured for it
    if((tor_proxy != NULL) && (tor_proxy_port != -1) && (tor_proxy_protocol != -1)){
      curl_easy_setopt(curlobj, CURLOPT_PROXY, tor_proxy); 
      curl_easy_setopt(curlobj, CURLOPT_PROXYPORT, tor_proxy_port); 
      curl_easy_setopt(curlobj, CURLOPT_PROXYTYPE, tor_proxy_protocol); 
    }
    curl_easy_setopt(curlobj, CURLOPT_URL, onion_url);
    curl_easy_setopt(curlobj, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curlobj, CURLOPT_WRITEDATA, (void *)&resp);
    if(cookie != NULL){ curl_easy_setopt(curlobj, CURLOPT_COOKIE, cookie);  }
    res = curl_easy_perform(curlobj);
    if(res != CURLE_OK){
      const char* cerror = curl_easy_strerror(res);
      SERR(s, "curl_easy_perform FAILED: curl code: %d curl strerror: %s\n", res, cerror);
    } else {
      double length = 0;
      char* type = NULL;
      resl = curl_easy_getinfo(curlobj, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &length);
      rest = curl_easy_getinfo(curlobj, CURLINFO_CONTENT_TYPE, &type);
      if((resl ==  CURLE_OK) && (rest ==  CURLE_OK)){
        size_t header_length = (size_t)length;
        if(1){
          SLOG(s, "Content-Type: %s\n", type);
          SLOG(s, "Content-Length: %" PRIu64 "\n", header_length);
          SLOG(s, "resp = %" PRIu64 " bytes\n", resp.buffer_size);
        }
        if(header_length == resp.buffer_size){
          onion_t signed_onion = resp.buffer;
          int retcode = apr_verify(public_key_fp, signed_onion);
          if(retcode){
            SLOG(s, "verifying onion SUCCEEDED: %d\n", retcode);
            retval = signed_onion;
          } else {
            SERR(s, "verifying onion FAILED: %d\n", retcode);
          }
        }
      } else {
        SERR(s, "fetching failed; ONLY got %"  PRIu64 " bytes\n", resp.buffer_size);
      }
    }
    curl_easy_cleanup(curlobj);
  }
  curl_global_cleanup();
  return retval;
}


apr_status_t signed_collection_to_file(server_rec* s, onion_t onion, const char* path, apr_pool_t* pool){
  apr_file_t* stream = NULL;
  apr_status_t status = apr_file_open(&stream, path, APR_WRITE | APR_TRUNCATE | APR_CREATE | APR_BINARY, APR_OS_DEFAULT, pool);
  if(status != APR_SUCCESS){
    char errbuf[256];
    apr_strerror(status, errbuf, sizeof(errbuf));
    SERR(s, "apr_file_open(%s): %s", path, errbuf);
  } else { 
  int i, errcode, onionc = 0;
  onion_t *onionv = NULL;
  onion_t collection = NULL;
  collection = (onion_t)(ONION_DATA(onion));
  errcode = apr_peel_collection_onion(collection, &onionc, &onionv);
  SLOG(s, "peeling: got %d onions\n", onionc);
  if(onionc > 0){
    for(i = 0; i < onionc; i++){
      onion_t onion = onionv[i];
      status = onion2stream(s, onion, stream);
      if(status != APR_SUCCESS){ return status; }
      free(onion);
    }
    free(onionv);
  }
  apr_file_close(stream);
  }
  return APR_SUCCESS;
}
