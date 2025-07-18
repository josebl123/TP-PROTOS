#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

#define MAX_USERS 10
#define MAX_ADMINS 3
#define DEFAULT_SOCKS_ADDR "0.0.0.0"
#define DEFAULT_SOCKS_PORT 1080
#define DEFAULT_MNG_ADDR "127.0.0.1"
#define DEFAULT_MNG_PORT 8080


struct users
{
    char* name;
    char* pass;
    bool is_admin; // true si es admin, false si es usuario normal
    bool is_added;
};

struct socks5args
{
    char* socks_addr;
    unsigned short socks_port;

    char* mng_addr;
    unsigned short mng_port;

    bool server_accepts_no_auth; // true si acepta conexiones sin autenticación, false si no

    bool disectors_enabled;

    struct users users[MAX_USERS];
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void
parse_args(const int argc, char** argv, struct socks5args* args);

#endif
