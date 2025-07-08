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
void
parse_client_args(const int argc, char** argv, struct clientArgs* args){

    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    int   bufsize     = 0;
    int   no_auth     = 0;
    char *port        = "8080"; // Default port, not used in this context
    char *addr        = "";
    char *add_user    = NULL;
    char *remove_user = NULL;
    char *make_admin  = NULL;
    char *login_user  = NULL;
    char *login_pass  = NULL;

    struct option longopts[] = {
            {"buffer-size", required_argument,  NULL, 'b'},
            {"no-auth",     no_argument,        NULL, 'n'},
            {"port",        required_argument,  NULL, 'p'},
            {"address",     required_argument,  NULL, 'a'},
            {"add-user",    required_argument,  NULL, 'u'},
            {"remove-user", required_argument,  NULL, 'r'},
            {"make-admin",  required_argument,  NULL, 'm'},
            {"login",       required_argument,  NULL, 'l'},
            {0,0,0,0}
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "b:nu:r:m:l:", longopts, NULL)) != -1) {
        switch (ch) {
            case 'b':
                bufsize = atoi(optarg);
                break;
            case 'n':
                no_auth = 1;
                break;
            case 'u':
                add_user = optarg;
                break;
            case 'r':
                remove_user = optarg;
                break;
            case 'm':
                make_admin = optarg;
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
                break;
            }
            case 'p':
                port = optarg;
                if (strlen(port) == 0 || atoi(port) <= 0 || atoi(port) > USHRT_MAX) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'a':
                addr = optarg;
                if (strlen(addr) == 0) {
                    fprintf(stderr, "Invalid address: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                fprintf(stderr,
                        "Usage: %s [options]\n"
                        "  -b, --buffer-size <n>\n"
                        "  -n, --no-auth\n"
                        "  -u, --add-user <user>\n"
                        "  -r, --remove-user <user>\n"
                        "  -m, --make-admin <user>\n"
                        "  -l, --login <user:pass>\n"
                        "  -p, --port <port>\n"
                        "  -a, --address <addr>\n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!login_user) {
        fprintf(stderr,
                "Error: --login <user:pass> is required.\n\n"
                "Usage: %s [options]\n"
                "  -b, --buffer-size <n>\n"
                "  -n, --no-auth\n"
                "  -u, --add-user <user>\n"
                "  -r, --remove-user <user>\n"
                "  -m, --make-admin <user>\n"
                "  -l, --login <user:pass>   (required)\n"
                "  -p, --port <port>\n"
                "  -a, --address <addr>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!addr) {
        fprintf(stderr, "Error: --address <addr> is required.\n\n"
                "Usage: %s [options]\n"
                "  -b, --buffer-size <n>\n"
                "  -n, --no-auth\n"
                "  -u, --add-user <user>\n"
                "  -r, --remove-user <user>\n"
                "  -m, --make-admin <user>\n"
                "  -l, --login <user:pass>   (required)\n"
                "  -p, --port <port>\n"
                "  -a, --address <addr>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    args->addr = addr; // Set the address for the client
    args->port = port; // Set the port for the client

    if (bufsize) {
        args->buffer_size = bufsize;
        args->type = BUFFER_SIZE;
    } else if (no_auth) {
        args->accepts_no_auth = true;
        args->type = ACCEPTS_NO_AUTH;
    } else if (add_user) {
        args->user.name = add_user;
        args->user.pass = login_pass; // Use the password from login
        args->type = ADD_USER;
    } else if (remove_user) {
        args->user.name = remove_user;
        args->type = REMOVE_USER;
    } else if (make_admin) {
        args->user.name = make_admin;
        args->type = MAKE_ADMIN;
    } else if (login_user && login_pass) {
        args->username = login_user;
        args->password = login_pass;
        args->type = BUFFER_SIZE; // Default type
    } else {
        fprintf(stderr, "Error: No valid options provided.\n");
        exit(EXIT_FAILURE);
    }

}
