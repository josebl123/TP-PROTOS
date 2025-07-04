// user_metrics_table.h
#ifndef USER_METRICS_TABLE_H
#define USER_METRICS_TABLE_H

#include <stdio.h>
#include "../metrics/metrics.h"

#define METRICS_TABLE_SIZE 128

void init_user_metrics_table(void);
user_metrics *get_or_create_user_metrics(const char *username);
user_metrics *find_user_metrics(const char *username);
void print_all_user_metrics(FILE *out);
void free_user_metrics_table(void);

#endif // USER_METRICS_TABLE_H
