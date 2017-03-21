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

#include "test.h"

/* test json */
int test_json_from_file(void) {

  char * file = "./resources/config_m2mi.json";
  char * json_str = json_from_file(file);
  if(json_str == NULL)
    fail();
  if(json_str[0] != '{')
    fail();
  done();
}

/* test crypto */
int test_load_rsa_private_key(void) {

  char * privKey_file = "./resources/privateKey.pem";
  RSA * privKey = load_rsa_private_key(privKey_file);
  if(privKey == NULL)
    fail();
  done();
}

int test_sha256_hash_file(void) {

  char * file = "./resources/test_file.pem";
  char * hash = sha256_hash_file(file);
  if(hash == NULL)
    fail();
  if(strcmp(hash, "gncH9Eubzs0pdjgWYXlN8V3XcWOUZWo4ERly+9h9nV4=") != 0)
    fail();
  done();
}

int test_rsa_sha256_sign_file(void) {

  char * privKey_file = "./resources/privateKey.pem";
  char * file = "./resources/test_file.pem";
  RSA * privKey = load_rsa_private_key(privKey_file);
  char * sig = rsa_sha256_sign_file(privKey, file);
  if(sig == NULL)
    fail();
  done();
}

int test_to_base64(void) {

  char * str = "This is an example of a string";
  char * base64 = to_base64(str);
  if(base64 == NULL)
    fail();
  if(strcmp(base64,"VGhpcyBpcyBhbiBleGFtcGxlIG9mIGEgc3RyaW5n") != 0)
    fail();
  done();
}

/* test https */
int test_HTTPS_client(void) {

  http_response * response;
	char * url = (char *)"https://www.google.com:443/#q=m2mi";

	HTTPSClient *client = new_https_client(url);
  if(client == NULL)
    fail();
	if(https_open(client) != 1)
    fail();
	if(https_set_basic_auth(client, "julien", "test") != 1)
    fail();
	if(https_set_content_type(client, URL_ENCODED) != 1)
    fail();
	response = https_post(client, "Hello Google");
	if(response->code != 200)
    fail();
	if(https_close(client) != 1)
    fail();

  done();
}

void run_test(void) {
	test(test_json_from_file, "load json from file");
  test(test_load_rsa_private_key, "load rsa private key from file");
  test(test_sha256_hash_file, "hash file with sha256");
  test(test_rsa_sha256_sign_file, "sign file with sha256 and rsa");
  test(test_to_base64, "encode string to base 64");
  test(test_HTTPS_client, "post data to google over https");
}
