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

#include "HTTPSClient.h"
#include "../log/log.h"


const char * PREFERRED_CIPHERS = "ECDHE-RSA-SPECK256-SHA256"; //"ALL:+AES:!CAMELLIA:!CHACHA20:!IDEA:!SEED:!aNULL:!eNULL"; 
const char * TRUST_CERTS = "../resources/geotrust.pem";
const long FLAGS = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;

static void init_openssl_library(void);
static void ssl_error(void);
#ifdef NDEBUG
static void print_cn_name(const char* label, X509_NAME* const name);
static void print_san_name(const char* label, X509* const cert);
static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
#endif

HTTPSClient * new_client(char * url) {

	HTTPSClient *client = NULL;
	URL *tmp = NULL;

	if(NULL == url) {
		return NULL;
	}
	else {
		tmp = (URL *)malloc(sizeof(URL));
		sscanf(url, "%99[^:]://%99[^:]:%99d%150[^\n]", tmp->scheme, tmp->hostname, &(tmp->port), tmp->path);
		debug("URL for HTTP client: [%s, %s, %d, %s]", tmp->scheme,tmp->hostname,tmp->port,tmp->path);
	}

	client = (HTTPSClient*)malloc(sizeof(HTTPSClient));
	if(client != NULL) {
		client->header=NULL;
		client->authorization = NULL;
		client->content_type = NULL;
		client->connection = NULL;
		client->url = tmp;

	}

    return client;
}

int client_set_content_type(HTTPSClient *client, CONTENT_TYPE type) {
	
	client->content_type = malloc(35);
	snprintf(client->content_type, 35, "%s", CONTENT_TYPE_STR[type]);
	return 1;
}

int client_set_basic_auth(HTTPSClient *client, char * username, char * password) {
	
	BIO *b64, *bio;
	BUF_MEM *bio_ptr;

	char credentials[100];
	snprintf(credentials, sizeof(credentials), "%s:%s", username, password);

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, bio);
	BIO_write(b64, credentials, strlen(credentials));
	BIO_flush(b64);   
    BIO_get_mem_ptr(bio, &bio_ptr); 
    BIO_set_close(bio, BIO_NOCLOSE);   
    BIO_free_all(b64); 

    client->authorization = malloc(bio_ptr->length + 9);
    snprintf(client->authorization, bio_ptr->length + 9, "Basic %s", bio_ptr->data);

    debug("Adding authorization header: %s", client->authorization);
	
	return 1;
}

int client_set_oauth2(HTTPSClient *client, char * token) {

    int len = strlen(token) + 10;
    client->authorization = malloc(len);
    snprintf(client->authorization, len, "Bearer %s", token);

    return 1;
}

int client_set_header(HTTPSClient *client, char * header) {

	client->header = malloc(200);
	snprintf(client->header, 200, "%s", header);
	return 1;
}

int client_open(HTTPSClient *client) {

	int res;
	SSL_CTX *ctx = NULL;
	BIO *web = NULL;
	SSL *ssl = NULL;
    URL *url = NULL;

    debug("Opening TLS connection...");

    if(client->url == NULL) {
    	error("Client not initialized.");
    	return 0;
    }
    url = client->url;

    client->connection = (tls_connection *)malloc(sizeof(tls_connection));
    if(client->connection == NULL) {
    	error("Failed to allocate space for tls connection.");
    	return 0;
    }

    init_openssl_library();
    
    const SSL_METHOD* method = TLS_method();    
    if(!(NULL != method))
    {
        error("Failed to get SSLv23_method.");
        ssl_error();
        return 0;
    }
    
    ctx = SSL_CTX_new(method);    
    if(!(ctx != NULL))
    {
        error("Failed to create new context.");
        return 0;
    }
    
	#ifndef NDEBUG
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	#endif

    SSL_CTX_set_verify_depth(ctx, 5);
	SSL_CTX_set_options(ctx, FLAGS);
    
    char realPath [PATH_MAX];
    realpath(TRUST_CERTS, realPath); 
    debug("Trusted Certificate Chain located in %s", realPath);
    res = SSL_CTX_load_verify_locations(ctx, realPath, NULL);
    if(!(1 == res))
    {
        debug("Failed to load trusted Certificate Chain.");
        ssl_error();
       // return 0;
    }
    
    web = BIO_new_ssl_connect(ctx);    
    if(!(web != NULL))
    {
        debug("Failed to create SSL connection object.");
        ssl_error();
        return 0;
    }
    
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s:%d", url->hostname, url->port); 
    res = BIO_set_conn_hostname(web, tmp);
    if(!(1 == res))
    {
        debug("Failed to set hostname and port.");
        ssl_error();
        return 0;
    }

    BIO_get_ssl(web, &ssl);
    if(!(ssl != NULL))
    {
        debug("Failed to get SSL connection object.");
        ssl_error();
        return 0;
    }

    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    if(!(1 == res))
    {
        debug("Failed to set cipher list");
        ssl_error();
        return 0;
    }

    res = SSL_set_tlsext_host_name(ssl, url->hostname);
    if(!(1 == res))
    {
        debug("Failed to set tlsext hostname.");
        ssl_error();
        return 0;
    }
    
    res = BIO_do_connect(web);
    if(!(1 == res))
    {
        debug("Connection error.");
        ssl_error();
       	return 0;
    }
    
    res = BIO_do_handshake(web);
    if(!(1 == res))
    {
        debug("Handshake error.");
        ssl_error();
        return 0;
    }
    
    /* Validate received certificate */
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) { 
    	X509_free(cert); 
    } 
    if(NULL == cert) {
        debug("No certificate presented by peer.");
        ssl_error();
        return 0;
    }
    res = SSL_get_verify_result(ssl);
    if(!(X509_V_OK == res))
    {
        debug("Certificate chain verification failed.");
        ssl_error();
        return 0;
    }

    client->connection->bio = web;
    client->connection->ctx = ctx;

    debug("done.");

    return 1;

}

http_response * client_get(HTTPSClient *client) {

	http_response * response = NULL;
    char request[512];
    int MAX_DATA_SIZE = 2000;
    
    debug("Sending HTTP GET request...");

    response = malloc(sizeof(http_response));
    response->data = calloc(MAX_DATA_SIZE, sizeof(char));
	        
	/* Build the request */                                                              
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\n", client->url->path, client->url->hostname );
	if(NULL != client->authorization) {
		snprintf(request, sizeof(request), "%sAuthorization: %s\r\n", request, client->authorization);
	}
	if(NULL != client->content_type) {
		snprintf(request, sizeof(request), "%sContent-Type: %s\r\n", request, client->content_type);
	}
	if(NULL != client->header) {
		snprintf(request, sizeof(request), "%s%s\r\n", request, client->header);
	}
	snprintf(request, sizeof(request), "%sConnection: close\r\n\r\n", request); 
	
	/* Send the request */ 
	BIO_puts(client->connection->bio, request);
        
    /* Get the response */    
    int len = 0;
    int size = 0;
    char * buff = malloc(MAX_DATA_SIZE);
    do {
        len = BIO_read(client->connection->bio, buff, sizeof(buff));
        if(len > 0) {
        	if(size + len > MAX_DATA_SIZE) {
        		realloc(response->data, MAX_DATA_SIZE);
        	}
        	memcpy(response->data + size, buff, len);
        }
        size += len;
    } while (len > 0 || BIO_should_retry(client->connection->bio));

    /* Parse the response to get the http code */
    sscanf(response->data, "%*s %d %*s", &(response->code)); 

    debug("done.");

    return response;
}

http_response * client_post(HTTPSClient *client, char * data) {

	http_response * response = NULL;
    char request[512];
    int MAX_DATA_SIZE = 2000;
    
    debug("Sending HTTP POST request...");

    response = malloc(sizeof(http_response));
    response->data = calloc(MAX_DATA_SIZE, sizeof(char));
	        
	/* Build the request */                                                              
    snprintf(request, sizeof(request), "POST %s HTTP/1.1\r\nHost: %s\r\n", client->url->path, client->url->hostname );
	if(NULL != client->authorization) {
		snprintf(request, sizeof(request), "%sAuthorization: %s\r\n", request, client->authorization);
	}
	if(NULL != client->content_type) {
		snprintf(request, sizeof(request), "%sContent-Type: %s\r\n", request, client->content_type);
	}
	if(NULL != client->header) {
		snprintf(request, sizeof(request), "%s%s\r\n", request, client->header);
	}
	snprintf(request, sizeof(request), "%sConnection: close\r\n", request); 
	if(NULL != data) {
		snprintf(request, sizeof(request), "%sContent-Length: %lu\r\n\r\n", request, sizeof(data));
		snprintf(request, sizeof(request), "%s%s\r\n", request, data); 
	} 
	else {
		snprintf(request, sizeof(request), "%sContent-Length: %d\r\n", request, 0);
		snprintf(request, sizeof(request), "%s\r\n\r\n", request);
	}
	#ifdef NDEBUG
	printf("%s", request);
	#endif
	
	/* Send the request */ 
	BIO_puts(client->connection->bio, request);
        
    /* Get the response */    
    int len = 0;
    int size = 0;
    char * buff = malloc(MAX_DATA_SIZE);
    do {
        len = BIO_read(client->connection->bio, buff, sizeof(buff));
        if(len > 0) { 
        	if(size + len > MAX_DATA_SIZE) {
        		realloc(response->data, MAX_DATA_SIZE);
        	}
        	memcpy(response->data + size, buff, len);
        }
        size += len;
    } while (len > 0 || BIO_should_retry(client->connection->bio));
    debug("response %s", response->data);
    /* Parse the response to get the http code */
    sscanf(response->data, "%*s %d %*s", &(response->code)); 

    debug("done.");

    return response;
}

int client_close(HTTPSClient *client) {
    
    debug("Closing HTTPS connection...");

    if(NULL != client->connection) {
    	if(NULL != client->connection->bio)
    		BIO_free_all(client->connection->bio);
    
    	if(NULL != client->connection->ctx)
        	SSL_CTX_free(client->connection->ctx);

        free(client->connection);
    }
	

    if(NULL != client->url)
    	free(client->url);

    debug("done.");

    return 1;
}

static void init_openssl_library(void)
{
    (void)SSL_library_init();
    SSL_load_error_strings();
                            
    #if defined (OPENSSL_THREADS)
        debug("Warning: thread locking is not implemented");
    #endif
}

static void ssl_error(void)
{
    unsigned long err = ERR_get_error();
    const char* const str = ERR_reason_error_string(err);
    if(str)
        fprintf(stderr, "SSL error: %s\n", str);
    else
        fprintf(stderr, "SSL error: %lu (0x%lx)\n", err, err);

}

#ifdef NDEBUG
static void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        debug("%s: %s", label, utf8);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        debug("%s: <not available>", label);
}

static void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;
    
    do
    {
        if(!cert) break; /* failed */
        
        names = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;
        
        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */
        
        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            
            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;
                
                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }
                
                if(len1 != len2) {
                    debug("Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d", len2, len1);
                }
                
                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if(utf8 && len1 && len2 && (len1 == len2)) {
                    debug("  %s: %s", label, utf8);
                    success = 1;
                }
                
                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
            {
                debug("Unknown GENERAL_NAME type: %d", entry->type);
            }
        }

    } while (0);
    
    if(names)
        GENERAL_NAMES_free(names);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        error("%s: <not available>", label);
    
}

static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    debug("verify_callback (depth=%d)(preverify=%d)", depth, preverify);
    
    /* Issuer is the authority we trust that warrants nothing useful */
    print_cn_name("Issuer (cn)", iname);
    
    /* Subject is who the certificate is issued to by the authority  */
    print_cn_name("Subject (cn)", sname);
    
    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs */
        print_san_name("Subject (san)", cert);
    }
    
    if(preverify == 0)
    {
        if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            debug("Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY");
        else if(err == X509_V_ERR_CERT_UNTRUSTED)
            debug("Error = X509_V_ERR_CERT_UNTRUSTED");
        else if(err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            debug("Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN");
        else if(err == X509_V_ERR_CERT_NOT_YET_VALID)
            debug("Error = X509_V_ERR_CERT_NOT_YET_VALID");
        else if(err == X509_V_ERR_CERT_HAS_EXPIRED)
            debug("Error = X509_V_ERR_CERT_HAS_EXPIRED");
        else if(err == X509_V_OK)
            debug("Error = X509_V_OK");
        else
            debug("Error = %d", err);
    }

    #if !defined(NDEBUG)
        return 1;
    #else
        return preverify;
    #endif
}
#endif