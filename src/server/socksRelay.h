#ifndef SOCKSRELAY_H
#define SOCKSRELAY_H
#include <sys/socket.h>
#include "selector.h"
unsigned handleRelayClientWrite(struct selector_key *key);
unsigned handleRelayClientRead(struct selector_key *key);
unsigned handleRelayRemoteWrite(struct selector_key *key);
unsigned handleRelayRemoteRead(struct selector_key *key);


#endif //SOCKSRELAY_H
