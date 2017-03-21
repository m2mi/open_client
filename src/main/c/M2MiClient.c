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

#include "M2MiClient.h"

M2MiClient * new_m2mi_client(const char * config_file) {

	/* We load the configuration file */
	char * config = json_from_file(config_file);

	/* We parse the configuration file */
	int i;
	int r;
	jsmn_parser p;
	jsmntok_t t[15];

	jsmn_init(&p);
	r = jsmn_parse(&p, config, strlen(config), t, sizeof(t)/sizeof(t[0]));
	if (r < 1 || t[0].type != JSMN_OBJECT) {
		error("Failed to parse configuration file with error %d.", r);
		return NULL;
	}

	char * node;
	char * auth_issuer;
	char * auth_url;
	char * auth_args[4];
	for (i = 1; i < r; i++) {
		if (jsoneq(config, &t[i], "node") == 0) {
			node = strndup(config + t[i+1].start, t[i+1].end-t[i+1].start);
			i++;
		}
		else if (jsoneq(config, &t[i], "auth_issuer") == 0) {
			auth_issuer = strndup(config + t[i+1].start, t[i+1].end-t[i+1].start);
			i++;
		}
		else if (jsoneq(config, &t[i], "auth_url") == 0) {
			auth_url = strndup(config + t[i+1].start, t[i+1].end-t[i+1].start);
			i++;
		}
		else if (jsoneq(config, &t[i], "auth_args") == 0) {
			if (t[i+1].type != JSMN_OBJECT) {
				continue;
			}
			int j;
			for (j = 0; j < t[i+1].size; j++) {
				auth_args[j] = strndup(config + t[i+j+2].start, t[i+j+2].end-t[i+j+2].start);
			}
			i += t[i+1].size + 1;
		}
		else {
			i++;
		}
	}

		if(node == NULL || auth_issuer == NULL) {
			error("Invalid configuration file.");
			return NULL;
		}

		/* We initialize the client */
		M2MiClient *client = malloc(sizeof(M2MiClient));
		if(NULL == client) {
			error("Failed to allocate memory for client.");
			return NULL;
		}
		client->host = node;
		client->token = NULL;

		/* We request an authorization token */
		if(strcmp(auth_issuer, "m2mi") == 0) {
			client->token = get_m2mi_token(auth_url, auth_args);
		}
		else if(strcmp(auth_issuer, "openam") == 0) {
			client->token = get_openam_token(auth_url, auth_args);
		}
		else {
			error("Unknown authentication issuer.");
			return NULL;
		}

		debug("Client initialized.");

		return client;
}

// M2MiClient * m2mi_init(const char * host, const char * m2mi_uid, const char * m2mi_password, const char * app_uid, const char * app_password) {
//
// 	debug("Initializing M2Mi Client...");
//
// 	M2MiClient *client = malloc(sizeof(M2MiClient));
// 	if(NULL == client) {
// 		error("Failed to allocate memory for client.");
// 		return NULL;
// 	}
//
// 	client->host = strdup(host);
// 	client->m2mi_uid = strdup(m2mi_uid);
// 	client->m2mi_password = strdup(m2mi_password);
// 	client->app_uid = strdup(app_uid);
// 	client->app_password = strdup(app_password);
// 	client->token = NULL;
//
// 	get_openam_token(client);
//
// 	debug("Client initialized.");
//
// 	return client;
// }

int m2mi_send(M2MiClient * client, char * data) {

	debug("Sending data to M2Mi Application.");

	if(client->token == NULL) {
		error("No token provided.");
		return -1;
	}

	char data_url[400];
	snprintf(data_url, sizeof(data_url), "%s/node/v2/rs/node/data/572c9b97faa1297094bac01c?device=358696048948767",client->host);

	HTTPSClient * https = new_https_client(data_url);
	https_open(https);
	https_set_oauth2(https, client->token->access);
	https_set_content_type(https, JSON);
	http_response * response = https_post(https, data);
	https_close(https);

	if(200 != response->code) {
		error("Failed to send data with HTTP error %d.", response->code);
		return -1;
	}

	return 1;
}

int m2mi_close(M2MiClient * client) {

	debug("Closing M2Mi Client...");

	free(client->host);
	free(client->m2mi_uid);
	free(client->m2mi_secret);
	if(client->token != NULL) {
		free(client->token->type);
		free(client->token->access);
		free(client->token->refresh);
		free(client->token->issuer);
	}
	free(client);

	debug("Client closed.");

	return 1;
}
