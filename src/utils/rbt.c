#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "rbt.h"

rbt_node* create_node(user_connection conn) {
    rbt_node* node = malloc(sizeof(rbt_node));
    node->conn = conn;
    node->color = RED;
    node->left = node->right = node->parent = NULL;
    return node;
}

void rotate_left(user_connection_tree* tree, rbt_node* x) {
    rbt_node* y = x->right;
    x->right = y->left;
    if (y->left) y->left->parent = x;
    y->parent = x->parent;
    if (!x->parent) tree->root = y;
    else if (x == x->parent->left) x->parent->left = y;
    else x->parent->right = y;
    y->left = x;
    x->parent = y;
}

void rotate_right(user_connection_tree* tree, rbt_node* y) {
    rbt_node* x = y->left;
    y->left = x->right;
    if (x->right) x->right->parent = y;
    x->parent = y->parent;
    if (!y->parent) tree->root = x;
    else if (y == y->parent->right) y->parent->right = x;
    else y->parent->left = x;
    x->right = y;
    y->parent = x;
}

void insert_fixup(user_connection_tree* tree, rbt_node* z) {
    while (z->parent && z->parent->color == RED) {
        if (z->parent == z->parent->parent->left) {
            rbt_node* y = z->parent->parent->right;
            if (y && y->color == RED) {
                z->parent->color = BLACK;
                y->color = BLACK;
                z->parent->parent->color = RED;
                z = z->parent->parent;
            } else {
                if (z == z->parent->right) {
                    z = z->parent;
                    rotate_left(tree, z);
                }
                z->parent->color = BLACK;
                z->parent->parent->color = RED;
                rotate_right(tree, z->parent->parent);
            }
        } else {
            rbt_node* y = z->parent->parent->left;
            if (y && y->color == RED) {
                z->parent->color = BLACK;
                y->color = BLACK;
                z->parent->parent->color = RED;
                z = z->parent->parent;
            } else {
                if (z == z->parent->left) {
                    z = z->parent;
                    rotate_right(tree, z);
                }
                z->parent->color = BLACK;
                z->parent->parent->color = RED;
                rotate_left(tree, z->parent->parent);
            }
        }
    }
    tree->root->color = BLACK;
}

void rbt_insert(user_connection_tree* tree, user_connection conn) {
    rbt_node* z = create_node(conn);
    rbt_node* y = NULL;
    rbt_node* x = tree->root;

    while (x != NULL) {
        y = x;
        if (z->conn.access_time < x->conn.access_time) x = x->left;
        else x = x->right;
    }

    z->parent = y;
    if (!y) tree->root = z;
    else if (z->conn.access_time < y->conn.access_time) y->left = z;
    else y->right = z;

    insert_fixup(tree, z);
}

rbt_node* rbt_search(rbt_node* node, time_t access_time) {
    if (!node || node->conn.access_time == access_time) return node;
    if (access_time < node->conn.access_time)
        return rbt_search(node->left, access_time);
    else
        return rbt_search(node->right, access_time);
}

void rbt_inorder(rbt_node* node) {
    if (!node) return;
    rbt_inorder(node->left);
    printf("Time: %ld\n", node->conn.access_time);
    rbt_inorder(node->right);
}

void rbt_free(rbt_node* node) {
    if (!node) return;
    rbt_free(node->left);
    rbt_free(node->right);
    free(node);
}
