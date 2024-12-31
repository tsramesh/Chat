#include "db.h"

void get_db_credentials(char * configfile, char **db_user, char **db_pass, char **db_name, char **db_host, char **db_port) {

    *db_user = GetConfigValue( configfile, "DB_USER");
    *db_pass = GetConfigValue( configfile, "DB_PASS");
    *db_name = GetConfigValue( configfile, "DB_NAME");
    *db_host = GetConfigValue( configfile, "DB_HOST");
    *db_port = GetConfigValue( configfile, "DB_PORT");
    return;
}

void ocilib_print_db_error(OCI_Error *err) {
    int err_type = OCI_ErrorGetType(err);
 
    if (err_type == OCI_ERR_WARNING) {
         printf("DATABASE WARNING: %s\n", OCI_ErrorGetString(err));
    } else {
        printf("DATABASE ERROR: %s\n", OCI_ErrorGetString(err) );
    }
}

OCI_Connection * ocilib_connect_to_db(char * configfile, OCI_Connection **cn) {
    char *db_user = NULL, *db_pass = NULL, *db_name = NULL, *db_host = NULL, *db_port = NULL;
    get_db_credentials(configfile, &db_user, &db_pass, &db_name, &db_host, &db_port);

    int conn_string_len = strlen(db_name) + strlen(db_host) + strlen(db_port) + 3;
    char * conn_string = malloc(conn_string_len);
    snprintf(conn_string, conn_string_len, "%s:%s/%s", db_host, db_port, db_name);

    if(*cn) ocilib_disconnect_from_db(*cn);

    OCI_Initialize(ocilib_print_db_error, NULL, OCI_ENV_DEFAULT);
    *cn = OCI_ConnectionCreate(conn_string, db_user, db_pass, OCI_SESSION_DEFAULT);
    if (!cn) {
        OCI_Cleanup();
        return NULL;
    }
    printf("OCILIB Succssfully connected to database %s, as user %s with password %s\n", db_name, db_user, db_pass);
    free(conn_string);
    return *cn;
}

void ocilib_disconnect_from_db( OCI_Connection *cn ) {
    OCI_ConnectionFree(cn);
    OCI_Cleanup();
    return;
}

// Function to check for errors
void odpic_print_db_error(dpiContext *context, dpiErrorInfo errorInfo) {
    if (errorInfo.code != 0) {
        fprintf(stderr, "Error (%s:%s): %s\n",
                errorInfo.fnName, errorInfo.action,
                errorInfo.message);
        exit(EXIT_FAILURE);
    }
}

// Function to connect to the Oracle database
dpiConn * odpic_connect_to_db(char * configfile, dpiConn **cn) {
    dpiErrorInfo errorInfo;

    char *db_user = NULL, *db_pass = NULL, *db_name = NULL, *db_host = NULL, *db_port = NULL;
    get_db_credentials(configfile, &db_user, &db_pass, &db_name, &db_host, &db_port);

    int conn_string_len = strlen(db_name) + strlen(db_host) + strlen(db_port) + 3;
    char * conn_string = malloc(conn_string_len);
    snprintf(conn_string, conn_string_len, "%s:%s/%s", db_host, db_port, db_name);

    if (dpiContext_create(DPI_MAJOR_VERSION, DPI_MINOR_VERSION, &context, &errorInfo) != DPI_SUCCESS) {
        odpic_print_db_error(context, errorInfo);
    }

    if (dpiConn_create(context, db_user, strlen(db_user), db_pass, strlen(db_pass), 
                       conn_string, strlen(conn_string), NULL, NULL, cn) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        odpic_print_db_error(context, errorInfo);
    }

    printf("ODPI-C Succssfully connected to database %s, as user %s with password %s\n", db_name, db_user, db_pass);
    return *cn;
}

// Function to disconnect from the Oracle database
void odpic_disconnect_from_db(dpiConn *conn) {
    dpiErrorInfo errorInfo;
    if (dpiConn_release(conn) != DPI_SUCCESS) {
        printf("ODPI-C Failed to release connection.\n");
        dpiContext_getError(context, &errorInfo);
        odpic_print_db_error(context, errorInfo);
        exit(EXIT_FAILURE);
    }
    printf("ODPI-C Disconnected from the database successfully.\n");
}

// Function to open a connection pool
dpiPool * odpic_open_session_pool(char * configfile, dpiPool **pl) {
    dpiErrorInfo errorInfo;

    char *db_user = NULL, *db_pass = NULL, *db_name = NULL, *db_host = NULL, *db_port = NULL;
    get_db_credentials(configfile, &db_user, &db_pass, &db_name, &db_host, &db_port);

    int conn_string_len = strlen(db_name) + strlen(db_host) + strlen(db_port) + 3;
    char * conn_string = malloc(conn_string_len);
    snprintf(conn_string, conn_string_len, "%s:%s/%s", db_host, db_port, db_name);

    if (dpiContext_create(DPI_MAJOR_VERSION, DPI_MINOR_VERSION, &context, &errorInfo) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        odpic_print_db_error(context, errorInfo);
        return NULL;
    }

    dpiCommonCreateParams commonParams;
    dpiPoolCreateParams poolParams;
    poolParams.minSessions = 1;
    poolParams.maxSessions = 10;
    poolParams.sessionIncrement = 1;
    poolParams.externalAuth = 0;
    poolParams.homogeneous = 1;

    dpiContext_initCommonCreateParams(context, &commonParams);
    dpiContext_initPoolCreateParams(context, &poolParams);

    if (dpiPool_create(context, db_user, strlen(db_user), db_pass, strlen(db_pass), 
                       conn_string, strlen(conn_string), &commonParams, &poolParams, pl) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        odpic_print_db_error(context, errorInfo);
        printf("ODPI-C session pool creation failed.\n");
        return NULL;
    }
    printf("ODPI-C session pool created successfully.\n");
    return *pl;
}

// Function to acquire a session from the connection pool
dpiConn * odpic_get_session_from_pool(dpiPool *pl) {
    dpiConn *cn;
    dpiErrorInfo errorInfo;
    if (dpiPool_acquireConnection(pl, NULL, 0, NULL, 0, NULL, &cn) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        odpic_print_db_error(context, errorInfo);
        printf("ODPI-C Failed to acquire a connection from the session pool.\n");
        return NULL;
    }
    printf("ODPI-C Connection acquired from pool successfully.\n");
    return cn;
}

// Function to release a session back to the connection pool
void odpic_release_session_to_pool(dpiConn *cn) {
    dpiErrorInfo errorInfo;
    if (dpiConn_release(cn) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        odpic_print_db_error(context, errorInfo);
        printf("ODPI-C Failed to release session back to pool.\n");
    } else printf("ODPI-C Session released to pool successfully.\n");
}

// Function to release a session back to the connection pool
void odpic_close_session_pool(dpiPool *pl) {
    dpiErrorInfo errorInfo;
    if (dpiPool_close(pl, DPI_MODE_POOL_CLOSE_FORCE) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        odpic_print_db_error(context, errorInfo);
        printf("ODPI-C Failed to close session pool.\n");
    } else printf("ODPI-C Session pool closed successfully.\n");
}