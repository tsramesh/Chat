#include "db.h"

void get_db_credentials(char * configfile, char **db_user, char **db_pass, char **db_name, char **db_host, char **db_port) {

    *db_user = GetConfigValue( configfile, "DB_USER");
    *db_pass = GetConfigValue( configfile, "DB_PASS");
    *db_name = GetConfigValue( configfile, "DB_NAME");
    *db_host = GetConfigValue( configfile, "DB_HOST");
    *db_port = GetConfigValue( configfile, "DB_PORT");
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Retrieved Oracle database details as: User:%s, Pass:%s, Instance:%s, host: %s, port: %s", *db_user, *db_pass, *db_name, *db_host, *db_port);

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

/**
 * Establishes a connection to an Oracle database using OCILIB.
 *
 * This function retrieves database credentials from a configuration file,
 * constructs the connection string, initializes OCILIB, and creates a connection.
 *
 * @param[in] configfile Path to the configuration file containing database credentials.
 * @param[out] cn Pointer to an OCI_Connection object. If a connection already exists,
 *                it will be disconnected and replaced with a new one.
 * @return OCI_Connection* Pointer to the created connection, or NULL if the connection fails.
 *
 * Note:
 * - The caller is responsible for ensuring the connection is cleaned up using `OCI_Cleanup`.
 * - Logs messages for debugging, errors, and warnings.
 */
OCI_Connection * ocilib_connect_to_db(char * configfile, OCI_Connection **cn) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting connection to Oracle database");

    // Variables to hold database credentials
    char *db_user = NULL, *db_pass = NULL, *db_name = NULL, *db_host = NULL, *db_port = NULL;

    // Retrieve database credentials from the configuration file
    get_db_credentials(configfile, &db_user, &db_pass, &db_name, &db_host, &db_port);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Retrieved database credentials from config file: %s", configfile);

    // Construct the connection string
    char * conn_string = fstring("%s:%s/%s", db_host, db_port, db_name);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Constructed connection string: %s", conn_string);

    // Disconnect any existing connection
    if (*cn) {
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Disconnecting existing database connection");
        ocilib_disconnect_from_db(*cn);
    }

    // Initialize OCILIB
    if (!OCI_Initialize(ocilib_print_db_error, NULL, OCI_ENV_DEFAULT)) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to initialize OCILIB");
        free(conn_string);
        return NULL;
    }
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "OCILIB initialized successfully");

    // Create a new database connection
    *cn = OCI_ConnectionCreate(conn_string, db_user, db_pass, OCI_SESSION_DEFAULT);
    if (!*cn) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to create OCILIB connection: %s", conn_string);
        OCI_Cleanup();
        free(conn_string);
        return NULL;
    }

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully connected to database %s as user %s", db_name, db_user);

    // Free the connection string memory
    free(conn_string);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Freed connection string memory");

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


/**
 * Establishes a connection to an Oracle database using ODPI-C.
 *
 * This function retrieves database credentials from a configuration file,
 * constructs the connection string, initializes the ODPI-C context, and creates a connection.
 *
 * @param[in] configfile Path to the configuration file containing database credentials.
 * @param[out] cn Pointer to a dpiConn object. This will hold the created connection.
 * @return dpiConn* Pointer to the created connection, or NULL if the connection fails.
 *
 * Note:
 * - The caller is responsible for ensuring the connection is cleaned up using `dpiConn_release` and `dpiContext_destroy`.
 * - Logs messages for debugging, errors, and warnings.
 */
dpiConn * odpic_connect_to_db(char * configfile, dpiConn **cn) {
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Starting connection to Oracle database using ODPI-C");

    dpiErrorInfo errorInfo;
    dpiContext *context = NULL;

    // Variables to hold database credentials
    char *db_user = NULL, *db_pass = NULL, *db_name = NULL, *db_host = NULL, *db_port = NULL;

    // Retrieve database credentials from the configuration file
    get_db_credentials(configfile, &db_user, &db_pass, &db_name, &db_host, &db_port);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Retrieved database credentials from config file: %s", configfile);

    // Construct the connection string
    char * conn_string = fstring("%s:%s/%s", db_host, db_port, db_name);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Constructed connection string: %s", conn_string);

    // Initialize the ODPI-C context
    if (dpiContext_create(DPI_MAJOR_VERSION, DPI_MINOR_VERSION, &context, &errorInfo) != DPI_SUCCESS) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to create ODPI-C context: %s", errorInfo.message);
        free(conn_string);
        return NULL;
    }
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "ODPI-C context initialized successfully");

    // Create a new database connection
    if (dpiConn_create(context, db_user, strlen(db_user), db_pass, strlen(db_pass),
                       conn_string, strlen(conn_string), NULL, NULL, cn) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to create ODPI-C connection: %s", errorInfo.message);
        dpiContext_destroy(context);
        free(conn_string);
        return NULL;
    }

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully connected to database %s as user %s", db_name, db_user);

    // Free the connection string memory
    free(conn_string);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Freed connection string memory");

    return *cn;
}


/**
 * Disconnects from an Oracle database using ODPI-C.
 *
 * This function releases the provided database connection and logs any errors that occur during the release process.
 *
 * @param[in] conn Pointer to the dpiConn object representing the connection to be released.
 *
 * Note:
 * - Exits the program with a failure code if the disconnection fails. This situation may need a change
 */
void odpic_disconnect_from_db(dpiConn *conn) {
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Attempting to disconnect from the Oracle database");

    dpiErrorInfo errorInfo;

    if (dpiConn_release(conn) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to release ODPI-C connection: %s", errorInfo.message);
        exit(EXIT_FAILURE);
    }

    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully disconnected from the Oracle database");
}

// Function to open a connection pool
/**
 * Opens a session pool for an Oracle database using ODPI-C.
 *
 * This function retrieves database credentials from a configuration file,
 * constructs the connection string, initializes the ODPI-C context, and creates a session pool.
 *
 * @param[in] configfile Path to the configuration file containing database credentials.
 * @param[out] pl Pointer to a dpiPool object. This will hold the created session pool.
 * @return dpiPool* Pointer to the created session pool, or NULL if the operation fails.
 *
 * Note:
 * - The caller is responsible for cleaning up the session pool using `dpiPool_release`.
 * - Logs messages for debugging, errors, and warnings.
 */
dpiPool *odpic_open_session_pool(char *configfile, dpiPool **pl) {
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Starting session pool creation using ODPI-C");

    dpiErrorInfo errorInfo;
    dpiContext *context = NULL;

    // Variables to hold database credentials
    char *db_user = NULL, *db_pass = NULL, *db_name = NULL, *db_host = NULL, *db_port = NULL;

    // Retrieve database credentials from the configuration file
    get_db_credentials(configfile, &db_user, &db_pass, &db_name, &db_host, &db_port);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Retrieved database credentials from config file: %s", configfile);

    // Construct the connection string
    int conn_string_len = strlen(db_name) + strlen(db_host) + strlen(db_port) + 3; // Extra space for ':', '/' and '\0'
    char *conn_string = malloc(conn_string_len);
    if (!conn_string) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ERR_%d: Memory allocation for connection string failed: %s", errno, strerror(errno));
        return NULL;
    }

    snprintf(conn_string, conn_string_len, "%s:%s/%s", db_host, db_port, db_name);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Constructed connection string: %s", conn_string);

    // Initialize the ODPI-C context
    if (dpiContext_create(DPI_MAJOR_VERSION, DPI_MINOR_VERSION, &context, &errorInfo) != DPI_SUCCESS) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to create ODPI-C context: %s", errorInfo.message);
        free(conn_string);
        return NULL;
    }
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "ODPI-C context initialized successfully");

    // Initialize pool creation parameters
    dpiCommonCreateParams commonParams;
    dpiPoolCreateParams poolParams;
    if (dpiContext_initCommonCreateParams(context, &commonParams) != DPI_SUCCESS ||
        dpiContext_initPoolCreateParams(context, &poolParams) != DPI_SUCCESS) {
        dpiContext_getError(context, &errorInfo);
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to initialize pool creation parameters: %s", errorInfo.message);
        dpiContext_destroy(context);
        free(conn_string);
        return NULL;
    }

    // Set pool parameters
    poolParams.minSessions = 1;
    poolParams.maxSessions = 10;
    poolParams.sessionIncrement = 1;
    poolParams.externalAuth = 0;
    poolParams.homogeneous = 1;

    // Log the pool parameters
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Session pool parameters: minSessions=%d, maxSessions=%d, sessionIncrement=%d",
                poolParams.minSessions, poolParams.maxSessions, poolParams.sessionIncrement);

    // Create the session pool
    if (dpiPool_create(context, db_user, strlen(db_user), db_pass, strlen(db_pass),
                       conn_string, strlen(conn_string), &commonParams, &poolParams, pl) != DPI_SUCCESS) {
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "Failed to create ODPI-C session pool: %s", errorInfo.message);
        dpiContext_getError(context, &errorInfo);
        dpiContext_destroy(context);
        free(conn_string);
        return NULL;
    }

    // Log success message
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Successfully created ODPI-C session pool for database %s", db_name);

    // Free the connection string memory
    free(conn_string);
    log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Freed connection string memory");

    // Log function exit
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Exiting function after creating session pool.");

    // Return the session pool pointer
    return *pl;
}



// Function to acquire a session from the connection pool
dpiConn * odpic_get_session_from_pool(dpiPool *pl) {
    dpiConn *cn;
    dpiErrorInfo errorInfo;

    // Log function entry at LOG_INFO level
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Entering function to acquire a connection from the pool.");

    // Try to acquire a connection from the session pool
    if (dpiPool_acquireConnection(pl, NULL, 0, NULL, 0, NULL, &cn) != DPI_SUCCESS) {
        // Log a critical failure if acquiring the connection fails
        log_message(LOG_CRITICAL, process, __func__, __FILE__, __LINE__, "Failed to acquire a connection from the session pool.");

        // Retrieve the error information from the context
        dpiContext_getError(context, &errorInfo);

        // Log the database error for debugging purposes
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Context error details:");
        odpic_print_db_error(context, errorInfo);

        // Log the failure at LOG_FATAL level, this indicates that the program cannot continue properly
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ODPI-C Failed to acquire a connection from the session pool.");
        
        // Exit the program if the error is critical
        return NULL;
    }

    // Log successful connection acquisition at LOG_INFO level
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "ODPI-C Connection acquired from pool successfully.");

    // Return the acquired connection
    return cn;
}


void odpic_release_session_to_pool(dpiConn *cn) {
    dpiErrorInfo errorInfo;

    // Log function entry at LOG_INFO level
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Entering function to release the connection back to the pool.");

    // Attempt to release the connection back to the session pool
    if (dpiConn_release(cn) != DPI_SUCCESS) {
        // Log critical failure if releasing the connection fails
        log_message(LOG_CRITICAL, process, __func__, __FILE__, __LINE__, "Failed to release the session back to the pool.");

        // Retrieve the error information from the context
        dpiContext_getError(context, &errorInfo);

        // Log the database error for debugging purposes
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Context error details:");
        odpic_print_db_error(context, errorInfo);

        // Log the failure message at LOG_FATAL level, as this is a critical failure
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ODPI-C Failed to release session back to pool.");
        
        // In case of failure, the program will be halted due to the LOG_FATAL level
    } else {
        // Log successful release at LOG_INFO level
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "ODPI-C Session released to pool successfully.");
    }

    // Log function exit at LOG_INFO level
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Exiting function after attempting to release session.");
}


// Function to release a session back to the connection pool
void odpic_close_session_pool(dpiPool *pl) {
    dpiErrorInfo errorInfo;

    // Log function entry at LOG_INFO level
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Entering function to close the session pool.");

    // Attempt to close the session pool with FORCE mode
    if (dpiPool_close(pl, DPI_MODE_POOL_CLOSE_DEFAULT /*DPI_MODE_POOL_CLOSE_FORCE*/) != DPI_SUCCESS) {
        // Log critical failure if closing the session pool fails
        log_message(LOG_CRITICAL, process, __func__, __FILE__, __LINE__, "Failed to close the session pool.");

        // Retrieve the error information from the context
        dpiContext_getError(context, &errorInfo);

        // Log the database error for debugging purposes
        log_message(LOG_DEBUG, process, __func__, __FILE__, __LINE__, "Context error details:");
        odpic_print_db_error(context, errorInfo);

        // Log the failure message at LOG_FATAL level, as this is a critical failure
        log_message(LOG_FATAL, process, __func__, __FILE__, __LINE__, "ODPI-C Failed to close session pool.");
        
        // In case of failure, the program will be halted due to the LOG_FATAL level
    } else {
        // Log successful closure at LOG_INFO level
        log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "ODPI-C Session pool closed successfully.");
    }

    // Log function exit at LOG_INFO level
    log_message(LOG_INFO, process, __func__, __FILE__, __LINE__, "Exiting function after attempting to close session pool.");
}
