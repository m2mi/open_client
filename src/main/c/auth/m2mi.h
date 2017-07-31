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

#ifndef _m2mi_auth_h
#define _m2mi_auth_h

#include "../https/HTTPSClient.h"
#include "../json/jsmn.h"
#include "../log/log.h"
#include "token.h"
#include "../crypto/crypto.h"

access_token * get_m2mi_token(auth_config * auth_config);
access_token * refresh_m2mi_token(auth_config * auth_config, access_token* token);
int update_certificate(auth_config * auth_config);

#endif
