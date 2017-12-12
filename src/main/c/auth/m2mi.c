/*
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
 *     William Bathurst
 *     Louis Lamoureux
 *     Geoffrey Barnard
 */

#include "m2mi.h"

static char * concat(const char * s1, const char * s2);
static access_token * getTokenFromResponse(http_response * response);
static int updateCertFromResponse(http_response * response, const char * pub_key_file, const char * priv_key_file);

 access_token * get_m2mi_token(auth_config * auth_config) {

   debug("Requesting Access token from M2Mi.");

   char * pub_key_file = auth_config->auth_args[0];
   char * priv_key_file = auth_config->auth_args[1];

   /* We calculate the hash of the public key */
   char * pub_hash = sha256_hash_file(pub_key_file);
   /* We load the private key */
   RSA * privKey = load_rsa_private_key(priv_key_file);
   /* We sign the hash with the private key */
   char * signed_hash = rsa_sha256_sign_file(privKey, pub_key_file); printf("signed %s\n", signed_hash);

   /* We create the request payload */
   int len = strlen(pub_hash) + strlen(signed_hash) + 71;
   char * data = calloc(len, sizeof(char));
   snprintf(data, len, "{\"id\": \"%s\", \"secret\": \"%s\", \"type\": \"device\", \"protocol\": \"M2MI_AUTH_V1\"}",pub_hash, signed_hash);

   /* We send the request */
   char * token_url = concat(auth_config->auth_url,"/token");
   HTTPSClient * https = new_https_client(token_url);
   https_open(https);
   https_set_content_type(https, JSON);
   http_response * response = https_post(https, data);
   https_close(https);

   free(data);
   free(token_url);

   if(200 == response->code) {
       access_token * token = getTokenFromResponse(response);
  		return token;
  	}
  	else {
  		error("Failed to get token. HTTP error %d.", response->code);
  		return NULL;
  	}
 }

 access_token * refresh_m2mi_token(auth_config * auth_config, access_token * token) {

     char * m2mi_url = auth_config->auth_url;
     int len = strlen(m2mi_url) + strlen(token->access) + strlen("/token?grant=refresh&token=") + 1;
     char * refresh_url = calloc(len, sizeof(char));
     snprintf(refresh_url,len,"%s/token?grant=refresh&token=%s", m2mi_url, token->access);

     /* We send the request */
     HTTPSClient * https = new_https_client(refresh_url);
     https_open(https);
     https_set_content_type(https, JSON);
     http_response * response = https_post(https, "");
     https_close(https);

     free(refresh_url);

     if(200 == response->code) {
         access_token * token = getTokenFromResponse(response);
    		return token;
     }
     else if(406 == response->code) {
         int res = update_certificate(auth_config);
         if(res > 0) {
             access_token * token = get_m2mi_token(auth_config);
             return token;
         }
         else {
             error("Failed to get the new certificate: error %d.", res);
        	 return NULL;
         }
     }
     else {
    	 error("Failed to get token. HTTP error %d.", response->code);
    	 return NULL;
     }
 }

 int update_certificate(auth_config * auth_config) {

     char * pub_key_file = auth_config->auth_args[0];
     char * priv_key_file = auth_config->auth_args[1];

     /* We calculate the auth credentials */
     char * pub_hash = sha256_hash_file(pub_key_file);
     RSA * privKey = load_rsa_private_key(priv_key_file);
     char * signed_hash = rsa_sha256_sign_file(privKey, pub_key_file);

     /* We compute de url */
     char * m2mi_url = auth_config->auth_url;
     int len = strlen(m2mi_url) + strlen("/update?type=device&id=&secret=") + strlen(pub_hash) + strlen(signed_hash) + 1;
     char * update_url = calloc(len, sizeof(char));
     snprintf(update_url,len,"%s/update?type=device&id=%s&secret=%s", m2mi_url, pub_hash, signed_hash);

     /* We send the request */
     HTTPSClient * https = new_https_client(update_url);
     https_open(https);
     https_set_content_type(https, JSON);
     http_response * response = https_get(https);
     https_close(https);

     free(update_url);

     if(200 == response->code) {
          return updateCertFromResponse(response, pub_key_file, priv_key_file);
     }
     else {
    	error("Failed to get token. HTTP error %d.", response->code);
    	return -1;
     }
 }

 static access_token * getTokenFromResponse(http_response * response) {

     debug("Extracting token from HTTP response");

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
            return NULL;
        }

        access_token * token = malloc(sizeof(access_token));

        /* We loop over the keys */
        for (i = 1; i < r; i++) {
            if (jsoneq(json_str, &t[i], "access") == 0) {
                token->access = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
                i++;
            } else if (jsoneq(json_str, &t[i], "refresh") == 0) {
                token->refresh = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
                i++;
            } else if (jsoneq(json_str, &t[i], "type") == 0) {
                token->type = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
                i++;
            } else if (jsoneq(json_str, &t[i], "issuer") == 0) {
                token->issuer = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
                i++;
            } else if (jsoneq(json_str, &t[i], "expires") == 0) {
                token->expires = strtol(json_str + t[i+1].start, NULL, 10);
                i++;
            } else {
                // we ignore the other keys (scope and id_token)
                i++;
            }
        }

        debug("Token: type = %s, issuer = %s, access = %s, expires = %ld", token->type, token->issuer, token->access, token->expires);

        return token;

 }

 static int updateCertFromResponse(http_response * response, const char * pub_key_file, const char * priv_key_file) {

     debug("Extracting new certificate from HTTP response");

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

        char * pubKey = NULL;
        char * privKey = NULL;

        /* We loop over the keys */
        for (i = 1; i < r; i++) {
            if (jsoneq(json_str, &t[i], "cert") == 0) {
                pubKey = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
                i++;
            } else if (jsoneq(json_str, &t[i], "privKey") == 0) {
                privKey = strndup(json_str + t[i+1].start, t[i+1].end-t[i+1].start);
                i++;
            } else {
                i++;
            }
        }
        if(pubKey != NULL) {
            FILE * f1 = fopen(pub_key_file, "w");
            if (f1 == NULL) {
                error("Error opening file %s.\n", pub_key_file);
                return -1;
            }
            fprintf(f1, "%s", pubKey);
            fclose(f1);
        }
        if(privKey != NULL) {
            FILE * f2 = fopen(priv_key_file, "w");
            if (f2 == NULL) {
                error("Error opening file %s.\n", priv_key_file);
                return -1;
            }
            fprintf(f2, "%s", privKey);
            fclose(f2);
        }
        return 1;
 }

 static char * concat(const char * s1, const char * s2) {
    const size_t len1 = strlen(s1);
    const size_t len2 = strlen(s2);
    char * result = malloc(len1+len2+1);
    if(result != NULL) {
        memcpy(result, s1, len1);
        memcpy(result+len1, s2, len2+1);
    }
    return result;
}
