#ifndef _https_h
#define _https_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>
#include "debug.h"

struct url_st {
	char *scheme;
    char *hostname;
    int port;
    char *path;
};
typedef struct url_st URL;

struct https_connection_st {
  	URL * url;
  	SSL_CTX *ctx;
  	BIO *bio;
};
typedef struct https_connection_st https_connection;

struct https_response_st {
	int code;
	char *data;
};
typedef struct https_response_st https_response;

int open_connection(char *url, https_connection *connection);
int close_connection(https_connection *connection);
int https_get(https_connection *connection, https_response *response);

#endif
