#ifndef RBT_H
#define RBT_H

#include <netinet/in.h>
#include <stdio.h>


typedef enum {
    NO_ERROR,
    SEND_ERROR,
    RECEIVE_ERROR,
    DNS_RESOLUTION_ERROR,
    SERVER_ERROR,
    UNSUPPORTED_INPUT_ERROR
} error_type;
enum socks5_response_status {
    SOCKS5_SUCCEEDED = 0x00,
    SOCKS5_GENERAL_FAILURE = 0x01,
    SOCKS5_CONNECTION_NOT_ALLOWED = 0x02,
    SOCKS5_NETWORK_UNREACHABLE = 0x03,
    SOCKS5_HOST_UNREACHABLE = 0x04,
    SOCKS5_CONNECTION_REFUSED = 0x05,
    SOCKS5_TTL_EXPIRED = 0x06,
    SOCKS5_COMMAND_NOT_SUPPORTED = 0x07,
    SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED = 0x08
    // 0x09 to 0xFF: unassigned
};

typedef struct {
    uint8_t is_ipv6;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } addr;
} ip_address;

typedef struct user_connection {
    time_t access_time;
    ip_address ip_origin;
    ip_address ip_destination;
    char * destination_name;
    uint16_t port_origin;
    uint16_t port_destination;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    enum socks5_response_status status;
} user_connection;

typedef enum { RED, BLACK } Color;

typedef struct rbt_node {
    user_connection conn;
    Color color;
    struct rbt_node* left;
    struct rbt_node* right;
    struct rbt_node* parent;
} rbt_node;

typedef struct {
    rbt_node* root;
} user_connection_tree;

void rbt_insert(user_connection_tree* tree, user_connection conn);
void rbt_free(rbt_node* node);
rbt_node* rbt_search(rbt_node* node, time_t access_time);
void rbt_inorder(rbt_node* node);
void print_rbt_inorder(FILE *out, const char *username, rbt_node *node);

#endif // RBT_H
