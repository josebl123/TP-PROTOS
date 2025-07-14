//
// Created by nicol on 7/7/2025.
//
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>
#include "args.h"
#include "user_metrics_table.h"
void
parse_client_args(const int argc, char** argv, struct clientArgs* args){

    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    int   bufsize     = 0;
    int   no_auth     = 0;
    int   no_no_auth = 0; // Flag for no authentication, not used in this context
    int   global_metrics = 0; // Flag for global metrics
    int  own_user_metrics = 0; // Flag for specific metrics, not used in this context
    char *specific_metrics_user = NULL; // User for specific metrics, not used in this context
    char *port        = "8080"; // Default port, not used in this context
    char *addr        = "127.0.0.1";
    char *add_user    = NULL;
    char *add_pass    = NULL; // Password for the user to add
    char *remove_user = NULL;
    char *make_admin  = NULL;
    char *login_user  = NULL;
    char *login_pass  = NULL;

    struct option longopts[] = {
            {"buffer-size", required_argument,  NULL, 'b'},
            {"no-auth",     no_argument,        NULL, 'n'},
            {"no-no-auth", no_argument, NULL, 'N'},
            {"global-metrics", no_argument, NULL, 'G'},
            // {"own-user-metrics", no_argument, NULL, 'g'},
            {"specific-metrics", required_argument, NULL, 's'},
            {"port",        required_argument,  NULL, 'p'},
            {"address",     required_argument,  NULL, 'a'},
            {"add-user",    required_argument,  NULL, 'u'},
            {"remove-user", required_argument,  NULL, 'r'},
            {"make-admin",  required_argument,  NULL, 'm'},
            {"login",       required_argument,  NULL, 'l'},
            {0,0,0,0}
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "b:na:u:r:m:l:p:a:s:NG", longopts, NULL)) != -1) {
        switch (ch) {
            case 'b':
                bufsize = atoi(optarg);
                args->flag = "b";
                break;
            case 'n':
                no_auth = 1;
                args->flag = "n";
                break;
            case 'u': {
                char *sep = strchr(optarg, ':');
                if (!sep) {
                    fprintf(stderr, "Invalid --add-user argument, must be user:password\n");
                    exit(EXIT_FAILURE);
                }
                *sep = '\0';
                add_user = optarg;
                add_pass = sep + 1; // Password for the user to add
                if (strlen(add_user) == 0 || strlen(add_pass) == 0) {
                    fprintf(stderr, "Invalid --add-user argument, user and password must not be empty\n");
                    exit(EXIT_FAILURE);
                }
                args->flag = "u";
                break;
            }
            case 'r':
                remove_user = optarg;
                args->flag = "r";
                break;
            case 'm':
                make_admin = optarg;
                args->flag = "m";
                break;
            case 'l': {
                // expect optarg == "user:password"
                char *sep = strchr(optarg, ':');
                if (!sep) {
                    fprintf(stderr, "Invalid --login argument, must be user:password\n");
                    exit(EXIT_FAILURE);
                }
                *sep = '\0';
                login_user = optarg;
                login_pass = sep + 1;
                args->flag = "l";
                break;
            }
            case 'p':
                port = optarg;
                if (strlen(port) == 0 || atoi(port) <= 0 || atoi(port) > USHRT_MAX) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                args->flag = "p";
                break;
            case 'a':
                addr = optarg;
                if (strlen(addr) == 0) {
                    fprintf(stderr, "Invalid address: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                args->flag = "a";
                break;
            case 'G':
                global_metrics = 1; // Enable global metrics
                args->flag = "G";
                break;
            case 's':
                specific_metrics_user = optarg; // User for specific metrics, not used in this context
                if (strlen(specific_metrics_user) == 0) {
                    fprintf(stderr, "Invalid user for specific metrics: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                args->flag = "s";
                break;
            case 'N':
                no_no_auth = 1; // Flag for no authentication, not used in this context
                args->flag = "N";
                break;
            default:
                fprintf(stderr,
                        "Usage: %s [options]\n"
                        " If no option is given, the client will receive their own user metrics.\n"
                        "  -b, --buffer-size <n>\n"
                        "  -n, --no-auth\n"
                        "  -N, --no-no-auth\n"
                        "  -u, --add-user <user>\n"
                        "  -r, --remove-user <user>\n"
                        "  -m, --make-admin <user>\n"
                        "  -l, --login <user:pass>\n"
                        "  -p, --port <port>\n"
                        "  -a, --address <addr>\n"
                        "  -G, --global-metrics\n"
                        "  -s, --specific-metrics <user>\n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!login_user || !login_pass) {
        fprintf(stderr,
                "Error: --login <user:pass> is required.\n\n"
                "Usage: %s [options]\n"
                " If no option is given, the client will receive their own user metrics.\n"
                "  -b, --buffer-size <n>\n"
                "  -n, --no-auth\n"
                "  -N, --no-no-auth\n"
                "  -u, --add-user <user>\n"
                "  -r, --remove-user <user>\n"
                "  -m, --make-admin <user>\n"
                "  -l, --login <user:pass>   (required)\n"
                "  -p, --port <port>\n"
                "  -a, --address <addr>\n"
                "  -G, --global-metrics\n"
                "  -s, --specific-metrics <user>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    args->username = login_user; // Set the username for the client
    args->password = login_pass; // Set the password for the client

    if (!addr) {
        fprintf(stderr, "Error: --address <addr> is required.\n\n"
                "Usage: %s [options]\n"
                " If no option is given, the client will receive their own user metrics.\n"
                "  -b, --buffer-size <n>\n"
                "  -n, --no-auth\n"
                "  -N, --no-no-auth\n"
                "  -u, --add-user <user>\n"
                "  -r, --remove-user <user>\n"
                "  -m, --make-admin <user>\n"
                "  -l, --login <user:pass>   (required)\n"
                "  -p, --port <port>\n"
                "  -a, --address <addr>\n"
                "  -G, --global-metrics\n"
                "  -s, --specific-metrics <user>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    args->addr = addr; // Set the address for the client
    args->port = port; // Set the port for the client

    if (bufsize) {
        args->stats = false;
        args->buffer_size = bufsize;
        args->type = BUFFER_SIZE;
    } else if (no_auth) {
        args->stats = false;
        args->accepts_no_auth = true;
        args->type = ACCEPTS_NO_AUTH;
    } else if (add_user) {
        if (strcmp(add_user, ANONYMOUS_USER) == 0) {
            fprintf(stderr, "El nombre de usuario 'anonymous' está reservado y no puede ser utilizado.\n");
            exit(EXIT_FAILURE);
        }
        args->stats = false;
        args->user.name = add_user;
        args->user.pass = add_pass;
        args->type = ADD_USER;
    } else if (remove_user) {
        args->stats = false;
        args->user.name = remove_user;
        args->type = REMOVE_USER;
    } else if (make_admin) {
        args->stats = false; // Disable stats for make admin
        args->user.name = make_admin;
        args->type = MAKE_ADMIN;
    } else if (global_metrics ) {
        args->stats = true; // Enable global metrics
    }
    else if (specific_metrics_user) {
        args->stats = true; // Enable specific user metrics
        args->target_user = specific_metrics_user; // Set the target user for specific metrics
    } else if (no_no_auth) {
        args->stats = false; // Disable stats for no authentication
        args->accepts_no_auth = false; // Disable accepting no authentication
        args->type = ACCEPTS_NO_AUTH; // Set the type to ACCEPTS_NO_AUTH
    }
    else {
        own_user_metrics = 1;
        args->flag = "default";
        args->stats = true;
        args->target_user = args->username;
    }

}
