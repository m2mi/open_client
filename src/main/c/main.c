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

#include "test/test.h"
#include "M2MiClient.h"

char * getAbsolutePath(const char * file);

int main(int argc, char *argv[]) {

	//run_test();

		char * data = "{\"GlossSee\":\"bright\",\"SortAs\":\"apple\",\"ID\":\"123456789\"}";
		char * config = "config_m2mi.json";

		char * configFile = getAbsolutePath(config);
		M2MiClient * client = new_m2mi_client(configFile);
	 	int result = m2mi_send(client, data);
		if(result > 0) {
			printf("Data sent.");
		}
		m2mi_close(client);
		free(configFile);
	return 1;

}

char * getAbsolutePath(const char * file) {

		char currentDir[1024];
		char * absoluteFile;

		getcwd(currentDir, sizeof(currentDir));
		absoluteFile = calloc(strlen(currentDir) + 12 + strlen(file), sizeof(char));
		if(!strcmp(currentDir + strlen(currentDir) - 4, "/bin")) {
				memcpy(absoluteFile, currentDir, strlen(currentDir) - 4);
				memcpy(absoluteFile + strlen(currentDir) - 4, "/resources/", 11);
				memcpy(absoluteFile + strlen(currentDir) + 7, file, strlen(file));
		}
		else{
				memcpy(absoluteFile, currentDir, strlen(currentDir));
				memcpy(absoluteFile + strlen(currentDir), "/resources/", 11);
				memcpy(absoluteFile + strlen(currentDir) + 11, file, strlen(file));
		}

		return absoluteFile;
}
