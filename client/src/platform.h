/* Misc platform specialities */
#ifndef PLATFORM_H
#define PLATFORM_H 1

#include <inttypes.h>
#include <assert.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif

#ifndef PRIsizet
#define PRIsizet "zd"
#endif

#ifdef __GNUC__
#define PACKED __attribute__((packed))
#define ALIGNED __attribute__((aligned))
#define UNUSED __attribute__ ((__unused__))
#else
#define PACKED
#define ALIGNED
#define UNUSED
#endif

#ifndef _WIN32
#define PATH_SEPARATOR "/" 
#else
#define PATH_SEPARATOR "\\" 
#endif 

/* More Windows specifics */
#ifdef _WIN32

#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <winbase.h>
#include <string.h>
#include <stdio.h>

char *mkdtemp(char *tmpl);

#define strdup(x) _strdup(x)

#endif /* _WIN32 */

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#endif /* PLATFORM_H */
