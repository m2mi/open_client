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

#include "https/HTTPSClient.h"
#include "json/json.h"
#include "json/jsmn.h"
#include "log/log.h"
#include "auth/openam.h"
#include "auth/token.h"
#include "auth/m2mi.h"
#include "crypto/crypto.h"
#include <string.h>
#include <time.h>

typedef struct M2MiClient_st {
	char * gateway;
	auth_config * auth;
	access_token * token;
} M2MiClient;

M2MiClient * new_m2mi_client(const char * config_file);
int m2mi_send(M2MiClient * client, char * data);
int m2mi_close(M2MiClient * client);

#endif
