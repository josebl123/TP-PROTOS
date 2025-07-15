#ifndef TCP_SERVER_CONFIG_UTIL_H
#define TCP_SERVER_CONFIG_UTIL_H

#include "../selector.h"

unsigned attempt_send_bad_request_error(struct selector_key *key);
void handle_config_read(struct selector_key *key);
void handle_config_close(struct selector_key *key);
void handle_server_config_close(struct selector_key *key);
void config_close(struct selector_key *key);
void config_read(struct selector_key *key);
void config_write(struct selector_key *key);
int attempt_tcp_config_connection(int serv_sock);


#endif
