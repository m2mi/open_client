# open-client

The M2Mi Open Client allows IoT security implementers the ability to secure end-to-end data transmissions. The Open Client enables
asset authentication using PKI as well as encryption using Speck. The solution is industry centric, meaning it is designed for specific industry compliance. This allows developers to quickly generate and deploy device clients that comply with their industry’s regulations.

STRUCTURE
The Open Client is written in C and integrates with the OpenSSL Speck library. It allows security implementers with the ability to register their assets against M2Mi’s Authentication Server and select the final endpoint where the asset should push its generated data.

###Example Usage

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
    
