#include "metrics.h"
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h> // para struct in_addr
#include "server/server.h"


#include "server/tcpServerUtil.h"


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
    metrics.login_errors = 0;
    metrics.host_unreachable = 0;
}

void metrics_new_connection(void) {
    metrics.total_connections++;
    metrics.current_connections++;
    if (metrics.current_connections >= MAX_CONNECTIONS) {
        selector_set_interest(selector, master_socket, OP_NOOP); // Disable listening for new connections
    }
}

void metrics_add_host_unreachable_error(void) {
    metrics.host_unreachable++;
}

void add_new_login_error(void) {
    metrics.login_errors++;
}

void metrics_connection_closed(void) {
    if (metrics.current_connections > 0) {
        metrics.current_connections--;
        selector_set_interest(selector, master_socket, OP_READ); // Re-enable listening for new connections
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

void user_metrics_init(user_metrics* um) {
    if (!um) return;
    um->connections_tree.root = NULL;
    um->total_connections = 0;
    um->total_bytes_sent = 0;
    um->total_bytes_received = 0;
}

void user_metrics_add_connection(user_metrics* um, const user_connection* new_conn_data) {
    if (!um || !new_conn_data) return;
    rbt_insert(&um->connections_tree, *new_conn_data);
    um->total_connections++;
    um->total_bytes_sent += new_conn_data->bytes_sent;
    um->total_bytes_received += new_conn_data->bytes_received;
}

void user_metrics_free(user_metrics* um) {
    if (!um) return;
    rbt_free(um->connections_tree.root);
    um->connections_tree.root = NULL;
    um->total_connections = 0;
    um->total_bytes_sent = 0;
    um->total_bytes_received = 0;
}

void print_connection_line(FILE *out, const char *username, const user_connection *conn) {
    if (!out || !conn || !username) return;

    char time_str[32];
    struct tm tm_utc;
    gmtime_r(&conn->access_time, &tm_utc);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    char ip_origin_str[INET6_ADDRSTRLEN];
    if (conn->ip_origin.is_ipv6) {
        inet_ntop(AF_INET6, &conn->ip_origin.addr.ipv6, ip_origin_str, sizeof(ip_origin_str));
    } else {
        inet_ntop(AF_INET, &conn->ip_origin.addr.ipv4, ip_origin_str, sizeof(ip_origin_str));
    }
    fprintf(out, "%-20s | %-10s | %-4s | %-35s | %-6u | %-20s | %-6u | %-6d | %-10lu | %-10lu\n",
        time_str,
        username,
        "A",
        ip_origin_str,
        conn->port_origin,
        conn->destination_name ? conn->destination_name : "-",
        conn->port_destination,
        conn->status,
        conn->bytes_sent,
        conn->bytes_received
    );
}



void print_user_metrics_tabbed(user_metrics *um, const char *username, FILE *out) {
    if (!um || !username || !out) return;
    if (um->connections_tree.root == NULL) {
        fprintf(out, "\nNo connections found for user %s.\n\n", username);
        return;
    }
    print_rbt_inorder(out, username, um->connections_tree.root);
}
void print_all_users_metrics_tabbed(user_metrics *um, const char *username, FILE *out) {
    if (!um || !username || !out) return;
    print_rbt_inorder(out, username, um->connections_tree.root);
}


void user_connection_init(user_connection *conn) {
    if (!conn) return;
    memset(conn, 0, sizeof(user_connection));
    conn->access_time = time(NULL);
    conn->destination_name = NULL;
    conn->status = -1;  // o lo que uses como valor por defecto
}


void fill_ip_address_from_origin(ip_address *dest, struct originInfo *origin) {
    if (origin->addressType == IPV4) {
        dest->is_ipv6 = 0;
        dest->addr.ipv4.s_addr = origin->address.ipv4; // Asigno el uint32_t al campo s_addr
    } else if (origin->addressType == IPV6) {
        dest->is_ipv6 = 1;
        dest->addr.ipv6 = origin->address.ipv6;
    } else {
        dest->is_ipv6 = 0;
        dest->addr.ipv4.s_addr = 0;
    }
}

void print_global_metrics(FILE *out) {
    if (!out) return;
    fprintf(out, "\n==== GLOBAL METRICS ====\n");
    fprintf(out,
        "total_connections: %lu\n"
        "current_connections: %lu\n"
        "bytes_client_to_remote: %lu\n"
        "bytes_remote_to_client: %lu\n"
        "dns_resolutions_connections: %lu\n"
        "send_errors: %lu\n"
        "receive_errors: %lu\n"
        "dns_resolution_errors: %lu\n"
        "ipv4_connections: %lu\n"
        "ipv6_connections: %lu\n"
        "server_errors: %lu\n"
        "auth_errors: %lu\n"
        "unsupported_input: %lu\n"
        "host_unreachable: %lu\n\n",
        metrics.total_connections,
        metrics.current_connections,
        metrics.bytes_client_to_remote,
        metrics.bytes_remote_to_client,
        metrics.dns_resolutions_connections,
        metrics.send_errors,
        metrics.receive_errors,
        metrics.dns_resolution_errors,
        metrics.ipv4_connections,
        metrics.ipv6_connections,
        metrics.server_errors,
        metrics.login_errors,
        metrics.unsupported_input,
        metrics.host_unreachable
    );
}

void print_global_metrics_tabbed(FILE *out) {
    if (!out) return;

    fprintf(out, "Metric\tValue\n");
    fprintf(out, "total_connections\t%lu\n", metrics.total_connections);
    fprintf(out, "current_connections\t%lu\n", metrics.current_connections);
    fprintf(out, "bytes_client_to_remote\t%lu\n", metrics.bytes_client_to_remote);
    fprintf(out, "bytes_remote_to_client\t%lu\n", metrics.bytes_remote_to_client);
    fprintf(out, "dns_resolutions_connections\t%lu\n", metrics.dns_resolutions_connections);
    fprintf(out, "send_errors\t%lu\n", metrics.send_errors);
    fprintf(out, "receive_errors\t%lu\n", metrics.receive_errors);
    fprintf(out, "dns_resolution_errors\t%lu\n", metrics.dns_resolution_errors);
    fprintf(out, "ipv4_connections\t%lu\n", metrics.ipv4_connections);
    fprintf(out, "ipv6_connections\t%lu\n", metrics.ipv6_connections);
    fprintf(out, "server_errors\t%lu\n", metrics.server_errors);
    fprintf(out, "unsupported_input\t%lu\n", metrics.unsupported_input);
    fprintf(out, "auth_errors\t%lu\n", metrics.login_errors);
    fprintf(out, "host_unreachable\t%lu\n", metrics.host_unreachable);
}





