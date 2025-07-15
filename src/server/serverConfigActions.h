//
// Created by nicol on 7/12/2025.
//

#ifndef SERVERCONFIGACTIONS_H
#define SERVERCONFIGACTIONS_H
#include "selector.h"
unsigned handle_admin_buffer_size_change_read(struct selector_key * key);
unsigned handle_admin_buffer_size_change_write(struct selector_key * key);
unsigned handle_admin_accepts_no_auth_write(struct selector_key * key);
unsigned handle_admin_rejects_no_auth_write(struct selector_key * key);
unsigned handle_admin_add_user_read(struct selector_key * key);
unsigned handle_admin_add_user_write(struct selector_key * key);
unsigned handle_admin_remove_user_read(struct selector_key * key);
unsigned handle_admin_remove_user_write(struct selector_key * key);
unsigned handle_admin_make_admin_read(struct selector_key * key);
unsigned handle_admin_make_admin_write(struct selector_key * key);
unsigned handle_admin_metrics_write( struct selector_key * key);
unsigned handle_user_metrics_write(struct selector_key * key);
unsigned attempt_admin_accepts_auth_write(struct selector_key *key, bool accepts);
unsigned attempt_admin_metrics_write(struct selector_key *key);
unsigned attempt_user_metrics_write(struct selector_key *key);
unsigned generic_write(struct selector_key * key, unsigned next_state, unsigned current_state);
unsigned send_metrics_fail_response(struct selector_key * key);


#endif //SERVERCONFIGACTIONS_H
