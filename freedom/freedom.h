#ifndef _FREEDOM_H_
#define _FREEDOM_H_

#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>

#define MOD_FREEDOM_VERSION_STRING         "1.01"
#define MOD_FREEDOM_RESPONSE_POOL_SIZE     10
#define MOD_FREEDOM_RESPONSE_MAX_LENGTH    1024

#define MOD_FREEDOM_UPDATE_FLAG            "rlfupdate"
#define MOD_FREEDOM_UPDATE_CONTENT         "rlfile"


/* flip for yada yada */
#define  VERBOSE  1

static const char freedom_fallback[] =
  "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n"
  "<html><head><title>Apache Freedom Module</title></head>"
  "<body><h1> Version "
  MOD_FREEDOM_VERSION_STRING
  "</h1></body></html>";


#define RERR(REQUEST, FMT, ...)  ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, REQUEST, FMT, __VA_ARGS__)
#define SERR(REQUEST, FMT, ...)  ap_log_error(APLOG_MARK, APLOG_ERR, 0, REQUEST, FMT, __VA_ARGS__)

#if VERBOSE
#define RLOG(REQUEST, FMT, ...) ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, REQUEST, FMT, __VA_ARGS__)
#define SLOG(SERVER, FMT, ...) ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, SERVER, FMT, __VA_ARGS__)
#else
#define RLOG(REQUEST, FMT, ...) 
#define SLOG(SERVER, FMT, ...) 
#endif

#endif


