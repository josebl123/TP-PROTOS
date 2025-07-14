//
// Created by nicol on 7/12/2025.
//

#ifndef SERVERCONFIGACTIONS_H
#define SERVERCONFIGACTIONS_H
#include "selector.h"
unsigned handleAdminBufferSizeChangeRead(struct selector_key * key);
unsigned handleAdminBufferSizeChangeWrite(struct selector_key * key);
unsigned handleAdminAcceptsNoAuthWrite(struct selector_key * key);
unsigned handleAdminRejectsNoAuthWrite(struct selector_key * key);
unsigned handleAdminAddUserRead(struct selector_key * key);
unsigned handleAdminAddUserWrite(struct selector_key * key);
unsigned handleAdminRemoveUserRead(struct selector_key * key);
unsigned handleAdminRemoveUserWrite(struct selector_key * key);
unsigned handleAdminMakeAdminRead(struct selector_key * key);
unsigned handleAdminMakeAdminWrite(struct selector_key * key);
unsigned handleAdminMetricsWrite( struct selector_key * key);
unsigned handleUserMetricsWrite(struct selector_key * key);
unsigned attemptAdminAcceptsAuthWrite(struct selector_key *key, bool accepts);
unsigned attemptAdminMetricsWrite(struct selector_key *key);
unsigned attemptUserMetricsWrite(struct selector_key *key);
unsigned genericWrite(struct selector_key * key, unsigned next_state, unsigned current_state);


#endif //SERVERCONFIGACTIONS_H
