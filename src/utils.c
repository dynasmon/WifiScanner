#include "../include/utils.h"
#include <stdio.h>

void save_results(Device *devices, int count, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        return;
    }

    fprintf(f, "[\n");
    for (int i = 0; i < count; ++i) {
        fprintf(f, "  {\"ip\": \"%s\", \"mac\": \"%s\"}%s\n",
                devices[i].ip, devices[i].mac,
                i == count - 1 ? "" : ",");
    }
    fprintf(f, "]\n");
    fclose(f);
}
