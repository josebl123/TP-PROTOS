#include "metrics.h"
#include <stdio.h>

Metrics metrics;

void metrics_init(void) {
    metrics.total_connections = 0;
    metrics.current_connections = 0;
    metrics.bytes_client_to_remote = 0;
    metrics.bytes_remote_to_client = 0;
    metrics.dns_resolutions_connections = 0;
    metrics.send_errors = 0;
    metrics.receive_errors = 0;
    metrics.dns_resolution_errors = 0;
    metrics.ipv4_connections = 0;
    metrics.ipv6_connections = 0;
    metrics.server_errors = 0;
    metrics.unsupported_input = 0;
}


void metrics_new_connection(void) {
    metrics.total_connections++;
    metrics.current_connections++;
}

void metrics_connection_closed(void) {
    if (metrics.current_connections > 0) {
        metrics.current_connections--;
    }
}

void metrics_add_bytes_client_to_remote(size_t count) {
    metrics.bytes_client_to_remote += count;
}

void metrics_add_bytes_remote_to_client(size_t count) {
    metrics.bytes_remote_to_client += count;
}

void metrics_add_dns_resolution(void) {
    metrics.dns_resolutions_connections++;
}

void metrics_add_send_error(void) {
    metrics.send_errors++;
}

void metrics_add_receive_error(void) {
    metrics.receive_errors++;
}

void metrics_add_dns_resolution_error(void) {
    metrics.dns_resolution_errors++;
}

void metrics_add_ipv4_connection(void) {
    metrics.ipv4_connections++;
}

void metrics_add_ipv6_connection(void) {
    metrics.ipv6_connections++;
}

void metrics_add_server_error(void) {
    metrics.server_errors++;
}

void metrics_add_unsupported_input(void) {
    metrics.unsupported_input++;
}

void metrics_print(void) {
    printf("Total Connections: %zu\n", metrics.total_connections);
    printf("Current Connections: %zu\n", metrics.current_connections);
    printf("Bytes Client to Remote: %zu\n", metrics.bytes_client_to_remote);
    printf("Bytes Remote to Client: %zu\n", metrics.bytes_remote_to_client);
    printf("DNS Resolutions Connections: %zu\n", metrics.dns_resolutions_connections);
    printf("Send Errors: %zu\n", metrics.send_errors);
    printf("Receive Errors: %zu\n", metrics.receive_errors);
    printf("DNS Resolution Errors: %zu\n", metrics.dns_resolution_errors);
    printf("IPv4 Connections: %zu\n", metrics.ipv4_connections);
    printf("IPv6 Connections: %zu\n", metrics.ipv6_connections);
    printf("Server Errors: %zu\n", metrics.server_errors);
    printf("Unsupported Input: %zu\n", metrics.unsupported_input);
}



