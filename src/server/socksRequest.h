//
// Created by nicol on 7/5/2025.
//

#ifndef SOCKSREQUEST_H
#define SOCKSREQUEST_H
#include "selector.h"

unsigned connectWrite(struct selector_key *key);
// Handle reading the request from the client
unsigned handleRequestRead(struct selector_key *key);
unsigned handleRequestWrite(struct selector_key *key);

unsigned handleDomainResolve(struct selector_key *key);

unsigned sendFailureResponseClient(struct selector_key *key);
unsigned sendFailureResponseRemote(struct selector_key *key);

#endif //SOCKSREQUEST_H
