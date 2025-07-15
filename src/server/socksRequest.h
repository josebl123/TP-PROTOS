//
// Created by nicol on 7/5/2025.
//

#ifndef SOCKSREQUEST_H
#define SOCKSREQUEST_H
#include "selector.h"

unsigned connect_write(struct selector_key *key);
// Handle reading the request from the client
unsigned handle_request_read(struct selector_key *key);
unsigned handle_request_write(struct selector_key *key);

unsigned handle_domain_resolve(struct selector_key *key, void *data);
unsigned handle_callback(struct selector_key *key, void *data);

unsigned send_failure_response_client(struct selector_key *key);
unsigned send_failure_response_remote(struct selector_key *key);

#endif //SOCKSREQUEST_H
