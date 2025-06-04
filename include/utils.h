#ifndef UTILS_H
#define UTILS_H

#include <netinet/in.h>

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char mac[18];
} Device;

void save_results(Device *devices, int count, const char *filename);

#endif // UTILS_H
