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
 
#include <stdlib.h>
#include <stdio.h>

#include "M2MiClient.h"
#include "https/HTTPSClient.h"

void test_HTTPS_client(void);
void test_M2Mi_client(void);

const char * HOST = "https://node2.m2mi.net:9443";
const char * M2MI_UID = "m2mi";
const char * M2MI_PWD = "password2";
const char * APP_UID = "ddf3f076-1568-4913-8f05-8eced7157995";
const char * APP_PWD = "tW04t31G6yr";

int main(int argc, char *argv[]) {

	//test_HTTPS_client();
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

	char * data = "{\"ID\":\"12\",\"IMEI\":\"358696048948767\",\"LAT\":40.241799,\"LON\":-97.910156}";

	M2MiClient * client = m2mi_init(HOST, M2MI_UID, M2MI_PWD, APP_UID, APP_PWD);
	int res = m2mi_send(client, data);
	if(res > 0) {
		printf("Data sent.");
	}
	m2mi_close(client);
	
}