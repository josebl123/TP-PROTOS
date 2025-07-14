#ifndef TCP_SERVER_CONFIG_UTIL_H
#define TCP_SERVER_CONFIG_UTIL_H

#include "../selector.h"

unsigned attempt_send_bad_request_error(struct selector_key *key);
void handleConfigRead(struct selector_key *key);
void handleConfigClose(struct selector_key *key);
void handleServerConfigClose(struct selector_key *key);
void config_close(struct selector_key *key);
void config_read(struct selector_key *key);
void config_write(struct selector_key *key);
int acceptTCPConfigConnection(int servSock);


#endif
