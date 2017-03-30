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

#include "m2mi.h"

 access_token * get_m2mi_token(const char * m2mi_url, char** args) {

   debug("Requesting Access token from M2Mi.");

   char * pub_key_file = args[0];
   char * priv_key_file = args[1];

   /* We calculate the hash of the public key */
   char * pub_hash = sha256_hash_file(pub_key_file);
   /* We load the private key */
   RSA * privKey = load_rsa_private_key(priv_key_file);
   /* We sign the hash with the private key */
   char * signed_hash = rsa_sha256_sign_file(privKey, pub_key_file);

   /* We create the request payload */
   int len = strlen(pub_hash) + strlen(signed_hash) + 45;
   char * data = calloc(len, sizeof(char));
   snprintf(data, len, "{\"id\": \"%s\", \"secret\": \"%s\", \"type\": \"device\"}",pub_hash, signed_hash);

   /* We send the request */
   HTTPSClient * https = new_https_client(m2mi_url);
   https_open(https);
   https_set_content_type(https, JSON);
   http_response * response = https_post(https, data);
   https_close(https);

   if(200 == response->code) {

     debug("Parsing response from M2Mi.");

  		// int i;
  		// int r;
  		// jsmn_parser p;
  		// jsmntok_t t[15]; /* We expect no more than 15 tokens */
      //
  		// while(*response->data != '{') {
  		// 	response->data++;
  		// }
  		// char * json_str = response->data;
  		// while(*response->data != '}') {
  		// 	response->data++;
  		// }
  		// *(++response->data) = '\0';
      //
  		// jsmn_init(&p);
  		// r = jsmn_parse(&p, json_str, strlen(json_str), t, sizeof(t)/sizeof(t[0]));
  		// if (r < 1 || t[0].type != JSMN_OBJECT) {
  		// 	error("Failed to parse JSON with error %d.", r);
  		// 	return NULL;
  		// }
      //
  		// access_token * token = malloc(sizeof(access_token));
  		// token->issuer = strdup(m2mi_url);
      //
  		// /* We loop over the keys */
  		// for (i = 1; i < r; i++) {
  		// 	if (jsoneq(json_str, &t[i], "access_token") == 0) {
  		// 		token->access = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
  		// 		i++;
  		// 	} else if (jsoneq(json_str, &t[i], "refresh_token") == 0) {
  		// 		token->refresh = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
  		// 		i++;
  		// 	} else if (jsoneq(json_str, &t[i], "token_type") == 0) {
  		// 		token->type = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
  		// 		i++;
  		// 	} else if (jsoneq(json_str, &t[i], "expires_in") == 0) {
  		// 		token->expires = strtol(json_str + t[i+1].start, NULL, 0);
  		// 		i++;
  		// 	} else {
  		// 		// we ignore the other keys (scope and id_token)
  		// 		i++;
  		// 	}
  		// }
      //
  		// debug("Token: type = %s, issuer = %s, access = %s, expires = %ld", token->type, token->issuer, token->access, token->expires);
      //
  		// return token;
  	}
  	else {
  		error("Failed to get token. HTTP error %d.", response->code);
  		return NULL;
  	}

 }
