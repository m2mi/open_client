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

#include "json.h"

char * json_from_file(const char * json_file) {

  char * json_str;
	int file_size;
	FILE * file = fopen(json_file, "rb");

	if(file == NULL) {
		error("Failed to load configuration file");
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	rewind(file);
	json_str = malloc((file_size + 1) * (sizeof(char)));
	fread(json_str, sizeof(char), file_size, file);
	fclose(file);
	json_str[file_size] = 0;

  return json_str;

}
