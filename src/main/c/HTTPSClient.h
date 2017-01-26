#ifndef _HTTPSClient_h
#define _HTTPSClient_h

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

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

typedef struct url_st {
	char scheme[6];
    char hostname[100];
    int port;
    char path[200];
} URL;

typedef struct tls_connection_st {
  	SSL_CTX *ctx;
  	BIO *bio;
} tls_connection;

typedef enum {
	JSON, URL_ENCODED
} CONTENT_TYPE;
static const char * CONTENT_TYPE_STR[] = {"application/json", "application/x-www-form-urlencoded"};

typedef struct HTTPSClient_st {
	URL * url;
	char * header;
	char * authorization;
	char * content_type;
	tls_connection * connection;
} HTTPSClient;

typedef struct http_response_st {
	int code;
	char *data;
} http_response;

HTTPSClient * new_client(char * url);
int client_open(HTTPSClient *client);
int client_set_content_type(HTTPSClient *client, CONTENT_TYPE type);
int client_set_basic_auth(HTTPSClient *client, char * username, char * password);
int client_set_oauth2(HTTPSClient *client, char * token);
int client_set_header(HTTPSClient *client, char * header);
http_response * client_get(HTTPSClient *client);
http_response * client_post(HTTPSClient *client, char * data);
int client_close(HTTPSClient *client);

#endif