# open-client

###Usage

    const char * HOST = "https://<my_m2mi_node_url>:9443";
    const char * M2MI_UID = "my_m2mi_uid";
    const char * M2MI_PWD = "my_m2mi_pwd";
    const char * APP_UID = "my_app_uid";
    const char * APP_PWD = "my_app_pwd";
    
    /* Initialize the client */
    M2MiClient * client = m2mi_init(HOST, M2MI_UID, M2MI_PWD, APP_UID, APP_PWD);
    
    /* Send data */
    char * data = "{\"LAT\":40.241799,\"LON\":-97.910156}";
    int res = m2mi_init(client, data);

    /* Close the client */
    res = m2mi_close(client);
    
