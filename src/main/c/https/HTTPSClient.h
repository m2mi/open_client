/*
 * (C) Copyright ${year} Machine-to-Machine Intelligence (M2Mi) Corporation, all rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Julien Niset
 */

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

#include "../log/log.h"

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

HTTPSClient * new_https_client(const char * url);
int https_open(HTTPSClient *client);
int https_set_content_type(HTTPSClient *client, CONTENT_TYPE type);
int https_set_basic_auth(HTTPSClient *client, char * username, char * password);
int https_set_oauth2(HTTPSClient *client, char * token);
int https_set_header(HTTPSClient *client, char * header);
http_response * https_get(HTTPSClient *client);
http_response * https_post(HTTPSClient *client, char * data);
int https_close(HTTPSClient *client);

#endif
