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

    int c;
    int nusers = 0;

  }
