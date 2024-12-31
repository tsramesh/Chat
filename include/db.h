#ifndef DB_H
#define DB_H

#include "common.h"

dpiContext *context;

void             get_db_credentials(char * configfile, char **db_user, char **db_pass, char **db_name, char **db_host, char **db_port);

void             ocilib_print_db_error(OCI_Error *err);
OCI_Connection * ocilib_connect_to_db(char * configfile, OCI_Connection **cn);
void             ocilib_disconnect_from_db( OCI_Connection *cn );

void      odpic_print_db_error(dpiContext *context, dpiErrorInfo errorInfo);
dpiConn * odpic_connect_to_db(char * configfile, dpiConn **cn);
void      odpic_disconnect_from_db(dpiConn *conn);
dpiPool * odpic_open_session_pool(char * configfile, dpiPool **pl);
void      odpic_close_session_pool(dpiPool *pl);
dpiConn * odpic_get_session_from_pool(dpiPool *pl);
void      odpic_release_session_to_pool(dpiConn *cn);
void      odpic_close_session_pool(dpiPool *pl);

#endif // DB_H