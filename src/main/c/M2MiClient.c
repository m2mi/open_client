#include "M2MiClient.h"

const char * OPENAM_PATH = "/openam/oauth2/m2mi/access_token";

M2MiClient * init_client(const char * host, const char * m2mi_uid, const char * m2mi_password, const char * app_uid, const char * app_password) {

	M2MiClient *client = NULL;

	client = malloc(sizeof(M2MiClient));
	if(client != NULL) {
		strcpy(client->host, host);
		strcpy(client->m2mi_uid, m2mi_uid);
		strcpy(client->m2mi_password, m2mi_password);
		strcpy(client->app_uid, app_uid);
		strcpy(client->app_password, app_password);
	}

	char openam_url[400];
	snprintf(openam_url, sizeof(openam_url), "%s%s?grant_type=password&scope=openid%%20read%%20write&username=%s&password=%s",
												host, OPENAM_PATH, app_uid, app_password);
	debug("New HTTP client.");
	HTTPSClient * https = new_client(openam_url);
	client_open(https);
	client_set_basic_auth(https, client->m2mi_uid, client->m2mi_password);
	client_set_content_type(https, URL_ENCODED);
	http_response * response = client_post(https, NULL);
	client_close(https);
	debug("code: %d, data: %s", response->code, response->data);

	return client;
}

M2MiClient * send_data(M2MiClient * client, char * data) {
	return NULL;
}