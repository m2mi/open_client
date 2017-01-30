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
 
#ifndef _M2MiClient_h
#define _M2MiClient_h

typedef struct access_token_st {
	char * type;
	char * access;
	char * refresh;
	long expires;
} access_token;

typedef struct M2MiClient_st {
	char * host;
	char * m2mi_uid;
	char * m2mi_password;
	char * app_uid;
	char * app_password;
	access_token * token;
} M2MiClient;


M2MiClient * init_client(const char * host, const char * m2mi_uid, const char * m2mi_password, const char * app_uid, const char * app_password);
int send_data(M2MiClient * client, char * data);
int close_client(M2MiClient * client);

#endif
