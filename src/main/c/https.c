#include "https.h"

const char * PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";
const long FLAGS = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;

static int parse_url(char * urlToParse, URL * url) {

	char scheme[5];
	char hostname[100];
    int port = 80;
    char path[100];

    sscanf(urlToParse, "%[^:]//%99[^:]:%99d/%99[^\n]", scheme, hostname, &port, path);

    url->scheme = scheme;
    url->hostname = hostname;
    url->port = port;
    url->path = path;

    return 1;

}

static void init_openssl_library(void)
{
    (void)SSL_library_init();
    SSL_load_error_strings();
                            
    /* Include <openssl/opensslconf.h> to get this define */
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

int open_connection(char *urlToParse, https_connection * connection) {

	int res;
	SSL_CTX *ctx = NULL;
	BIO *web = NULL, *out = NULL;
	SSL *ssl = NULL;
	URL url;

    debug("Opening HTTPS connection...");

	res = parse_url(urlToParse, &url);
	if(!(1 == res)) {
		debug("Failed to parse url.");
        return 0;
	}

    init_openssl_library();
    
    const SSL_METHOD* method = TLS_method();    
    if(!(NULL != method))
    {
        debug("Failed to get SSLv23_method.");
        ssl_error();
        return 0;
    }
    
    ctx = SSL_CTX_new(method);    
    if(!(ctx != NULL))
    {
        debug("Failed to create new context.");
        return 0;
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 5);
	SSL_CTX_set_options(ctx, FLAGS);
    
   // res = SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", NULL);
    if(!(1 == res))
    {
        debug("Failed to verify certificate chain.");
        ssl_error();
        return 0;
    }
    
    web = BIO_new_ssl_connect(ctx);    
    if(!(web != NULL))
    {
        debug("Failed to create SSL connection object.");
        ssl_error();
        return 0;
    }
    
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s:%d", url.hostname, url.port);
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

    res = SSL_set_tlsext_host_name(ssl, url.hostname);
    if(!(1 == res))
    {
        debug("Failed to set tlsext hostname.");
        ssl_error();
        return 0;
    }
    
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(!(NULL != out))
    {
        debug("Failed to create new fp.");
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

    connection->bio = web;
    connection->url = &url;
    connection->ctx = ctx;

    debug("done.");

    return 1;
}

int close_connection(https_connection *connection) {

    debug("Closing HTTPS connection...");

	if(NULL != connection->bio)
    	BIO_free_all(connection->bio);
    
    if(NULL != connection->ctx)
        SSL_CTX_free(connection->ctx);

    if(NULL != connection->url)
    	free(connection->url);

    debug("done.");

    return 1;
}

int https_get(https_connection *connection, https_response *response) {

	BIO *out = NULL;
    char data[512];
    int size = 0;

    debug("Sending HTTP GET request...");
	
    snprintf(data, sizeof(data), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connection->url->path, connection->url->hostname );
	BIO_puts(connection->bio, data);
        
    int len = 0;
    do {
        char buff[1536] = {};
        
        len = BIO_read(connection->bio, buff, sizeof(buff));
        
        if(len > 0)
            BIO_write(out, buff, len);

        size += len;
        
        /* BIO_should_retry returns TRUE unless there's an  */
        /* error. We expect an error when the server        */
        /* provides the response and closes the connection. */
        
    } while (len > 0 || BIO_should_retry(connection->bio));

    debug("done.");

    return size;

}