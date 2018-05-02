# Introduction

The M2Mi Open Client allows IoT security implementers the ability to secure end-to-end data transmissions. The Open Client enables asset authentication using PKI as well as encryption using Speck. The solution is industry centric, meaning it is designed for specific industry compliance. The Open Client is written in C and integrates with the OpenSSL Speck library. It allows security implementers with the ability to register their assets against M2Mi’s Authentication Server and select the final endpoint where the asset should push its generated data. The following steps outline the general steps needed to compile and prepare the client

## Instructions

Clone the M2Mi Client from GitHub into your development environment, for example:

`
git clone https://github.com/m2mi/open_client.git
`

Please take note of the directory where the software was installed. For example, if the software was cloned into the /usr/local/src directory then the top level directory of the code will be /usr/local/src/open-client. In the directory there would be the following:

`
user@host:/usr/local/src/open-client $ ls
bin  info.txt  LICENSE  mac-client  Makefile  README.md  resources  src
`

The code is written in the C Language and the main executable is located in the src/main/c/ directory and named main.c. 


NOTE: Subsequent instructions will detail modifying code and updating the certificate for the client.


Modify resources/config_m2mi.json. This file is used to indicate where the M2Mi server platform is located and the location of the public/private keys. The last two lines of the file will need to be updated. For Example:

`
"pubKey":"/usr/local/src/m2mi/git/open-client/resources/cert.pem",
"privKey":"/usr/local/src/m2mi/git/open-client/resources/privKey.pem"
`

One will also need to modify the Makefile located in at the top of the install directory to point towards the openssl-speck directories. For example, if OpenSSL was installed in /usr/local/ssl then use the following settings:

`
OPENSSL_INCLUDE = -I/user/local/ssl/include/
OPENSSL_LIB = -L/user/local/ssl/lib/`


This will let the compiler know where the OpenSSL library directories and header files are located.


If there isn’t a certificate available one can be created using the OpenSSL. In the client’s resources directory, run the following command to generate both the cert and private key:

`
openssl req -x509 -newkey rsa:4096 -keyout privKey.pem -out cert.pem -days 365 -sha256 -nodes
`

Note that the certificate and key location is defined in resources/config_m2mi.json. Either the newly created key and certificate should be installed to that directory, or the location should be updated with the desired location.


The base client code is ready for compilation. Use make clean and make to compile the code. The make dev can be used for debugging purposes.

`
make clean
make dev
`

### Example Usage

    const char *HOST     = "https://<service_url>";
    const char *M2MI_UID = "my_device_uid";
    const char *M2MI_PWD = "my_device_pwd";
    const char *APP_UID  = "my_app_uid";
    const char *APP_PWD  = "my_app_pwd";
    
    /* Initialize the client */
    M2MiClient * client = m2mi_init(HOST, M2MI_UID, M2MI_PWD, APP_UID, APP_PWD);
    
    /* Send data */
    char * data = "{\"LAT\":40.241799,\"LON\":-97.910156}";
    int res = m2mi_send(client, data);

    /* Close the client */
    res = m2mi_close(client);
    
