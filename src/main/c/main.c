#include <stdlib.h>
#include <stdio.h>

#include "M2MiClient.h"
#include "HTTPSClient.h"

void test_HTTPS_client(void);
void test_M2Mi_client(void);

const char * HOST = "https://node2.m2mi.net:9443";
const char * M2MI_UID = "m2mi";
const char * M2MI_PWD = "password2";
const char * APP_UID = "ddf3f076-1568-4913-8f05-8eced7157995";
const char * APP_PWD = "tW04t31G6yr";

int main(int argc, char *argv[]) {

	test_M2Mi_client();

}

void test_HTTPS_client(void) {

	http_response * response;
	char * url = (char *)"https://www.google.com:443/#q=m2mi";

	HTTPSClient *client = new_client(url);
	client_open(client);
	client_set_basic_auth(client, "julien", "test");
	client_set_content_type(client, URL_ENCODED);
	response = client_post(client, "Hello Google");
	printf("Response code: %d\n", response->code);
	client_close(client); 

}

void test_M2Mi_client(void) {

	M2MiClient * client = init_client(HOST, M2MI_UID, M2MI_PWD, APP_UID, APP_PWD);

	
}