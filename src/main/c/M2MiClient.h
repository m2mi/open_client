#ifndef _M2MiClient_h
#define _M2MiClient_h

#include "HTTPSClient.h"

typedef struct access_token_st {
	char * type;
	char * access;
	char * refresh;
	long expires;
} access_token;

typedef struct M2MiClient_st {
	char host[50];
	char m2mi_uid[50];
	char m2mi_password[50];
	char app_uid[100];
	char app_password[100];
	access_token * token;
} M2MiClient;


M2MiClient * init_client(const char * host, const char * m2mi_uid, const char * m2mi_password, const char * app_uid, const char * app_password);
int send_data(M2MiClient * client, char * data);

#endif
