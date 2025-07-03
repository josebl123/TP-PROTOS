#ifndef RBT_H
#define RBT_H

#include <netinet/in.h>

typedef enum {
    NO_ERROR,
    SEND_ERROR,
    RECEIVE_ERROR,
    DNS_RESOLUTION_ERROR,
    SERVER_ERROR,
    UNSUPPORTED_INPUT_ERROR
} error_type;

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
    error_type status;
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

#endif // RBT_H
