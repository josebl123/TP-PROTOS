#ifndef SOCKSRELAY_H
#define SOCKSRELAY_H
#include <sys/socket.h>
#include "selector.h"
unsigned handle_relay_client_write(struct selector_key *key);
unsigned handle_relay_client_read(struct selector_key *key);
unsigned handle_relay_remote_write(struct selector_key *key);
unsigned handle_relay_remote_read(struct selector_key *key);


#endif //SOCKSRELAY_H
