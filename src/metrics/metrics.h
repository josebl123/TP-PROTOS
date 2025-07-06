#ifndef METRICS_H
#define METRICS_H

#include <stddef.h>
#include "../utils/rbt.h"
#include <stdio.h>
#include "../server/tcpServerUtil.h"


typedef struct {
    uint64_t total_connections;
    uint64_t current_connections;
    uint64_t bytes_client_to_remote; // cliente → proxy → servidor remoto
    uint64_t bytes_remote_to_client; // servidor remoto → proxy → cliente
    uint64_t send_errors;
    uint64_t receive_errors;
    uint64_t dns_resolution_errors;
    uint64_t server_errors;
    uint64_t unsupported_input;
    uint64_t dns_resolutions_connections;
    uint64_t ipv4_connections;
    uint64_t ipv6_connections;
} Metrics;

typedef struct {
    user_connection_tree connections_tree;  // Red-Black Tree de conexiones
    uint64_t total_connections;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
} user_metrics;

extern Metrics metrics;

void metrics_init(void);
void metrics_new_connection(void);
void metrics_connection_closed(void);
void metrics_add_bytes_client_to_remote(size_t count);
void metrics_add_bytes_remote_to_client(size_t count);
void metrics_add_send_error(void);
void metrics_add_receive_error(void);
void metrics_add_dns_resolution_error(void);
void metrics_add_dns_resolution(void);
void metrics_add_ipv4_connection(void);
void metrics_add_ipv6_connection(void);
void metrics_add_server_error(void);
void metrics_add_unsupported_input(void);

void user_metrics_init(user_metrics* um);
void user_metrics_add_connection(user_metrics* um, const user_connection* new_conn_data);
void user_metrics_free(user_metrics* um);
void print_connection_line(FILE *out, const char *username, const user_connection *conn);
void print_user_metrics_tabbed(user_metrics *um, const char *username, FILE *out);
void user_connection_init(user_connection *conn);
void fill_ip_address_from_origin(ip_address *dest, struct originInfo *origin);
void print_global_metrics(FILE * out);
void print_global_metrics_tabbed(FILE *out);



#endif // METRICS_H
