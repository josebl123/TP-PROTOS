#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t total_connections;
    uint64_t current_connections;
    uint64_t bytes_client_to_remote; // cliente → proxy → servidor remoto
    uint64_t bytes_remote_to_client; // servidor remoto → proxy → cliente
    uint64_t send_errors;
    uint64_t receive_errors;
    uint64_t dns_resolution_errors;
    uint64_t server_errors;
    uint64_t unsupported_input;;
    uint64_t dns_resolutions_connections;
    uint64_t ipv4_connections;
    uint64_t ipv6_connections;
} Metrics;

extern Metrics metrics;

//TODO: Agregar un reseteo de las métricas

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
void metrics_print(void);


#endif
