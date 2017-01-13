#include <stdlib.h>
#include <stdio.h>

#include "debug.h"
#include "https.h"

int main(int argc, char *argv[]) {

	int res;
	https_connection connection;
	https_response response;

	//char * url = (char *)"http://node2.m2mi.net:9443";
	char * url = (char *)"https://www.random.org";

	open_connection(url, &connection);
//	https_get(&connection, &response);
	close_connection(&connection);

}