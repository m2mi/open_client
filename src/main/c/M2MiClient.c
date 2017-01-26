#include "M2MiClient.h"
#include "json/jsmn.h"
#include "log/log.h"

const char * OPENAM_PATH = "/openam/oauth2/m2mi/access_token";

static int get_openam_token(M2MiClient * client) {

	debug("Requesting Access token from OpenAM.");

	char token_url[400];
	snprintf(token_url, sizeof(token_url), "%s%s?grant_type=password&scope=openid%%20read%%20write&username=%s&password=%s",
												client->host, OPENAM_PATH, client->app_uid, client->app_password);

	HTTPSClient * https = new_client(token_url);
	client_open(https);
	client_set_basic_auth(https, client->m2mi_uid, client->m2mi_password);
	client_set_content_type(https, URL_ENCODED);
	http_response * response = client_post(https, NULL);
	client_close(https);
	
	if(200 == response->code) {

		debug("Parsing response from OpenAM.");

		int i;
		int r;
		jsmn_parser p;
		jsmntok_t t[15]; /* We expect no more than 15 tokens */

		while(*response->data != '{') {
			response->data++;	
		}
		char * json_str = response->data;
		while(*response->data != '}') {
			response->data++;
		}
		*(++response->data) = '\0';

		jsmn_init(&p);
		r = jsmn_parse(&p, json_str, strlen(json_str), t, sizeof(t)/sizeof(t[0]));
		if (r < 1 || t[0].type != JSMN_OBJECT) {
			error("Failed to parse JSON with error %d.", r);
			return -1;
		}

		access_token * token = malloc(sizeof(access_token));

		/* We loop over the keys */
		for (i = 1; i < r; i++) {
			if (jsoneq(json_str, &t[i], "access_token") == 0) {
				token->access = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
				i++;
			} else if (jsoneq(json_str, &t[i], "refresh_token") == 0) {
				token->refresh = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
				i++;
			} else if (jsoneq(json_str, &t[i], "token_type") == 0) {
				token->type = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
				i++;
			} else if (jsoneq(json_str, &t[i], "expires_in") == 0) {
				token->expires = strtol(json_str + t[i+1].start, NULL, 0);
				i++;
			} else {
				// we ignore the other keys (scope and id_token)
				i++;
			}
		}

		client->token = token;

		debug("Token: type = %s, access = %s, expires = %ld", client->token->type, client->token->access, client->token->expires);

		return 1;
	}
	else {
		debug("Failed to get token. HTTP error %d.", response->code);
		return -1;
	}
}

M2MiClient * init_client(const char * host, const char * m2mi_uid, const char * m2mi_password, const char * app_uid, const char * app_password) {

	M2MiClient *client = malloc(sizeof(M2MiClient));
	if(NULL == client) {
		error("Failed to allocate memory for client.");
		return NULL;
	}

	strcpy(client->host, host);
	strcpy(client->m2mi_uid, m2mi_uid);
	strcpy(client->m2mi_password, m2mi_password);
	strcpy(client->app_uid, app_uid);
	strcpy(client->app_password, app_password);
	client->token = NULL;

	get_openam_token(client); 

	return client;
}

int send_data(M2MiClient * client, char * data) {
	
	if(client->token == NULL) {
		error("No token provided.");
		return -1;
	}

	char data_url[400];
	snprintf(data_url, sizeof(data_url), "%snode/v2/rs/node/data/572c9b97faa1297094bac01c?device=358696048948767",client->host);

	HTTPSClient * https = new_client(data_url);
	client_open(https);
	client_set_oauth2(https, client->token->access);
	client_set_content_type(https, JSON);
	http_response * response = client_post(https, data);
	client_close(https);

	return 1;
}