#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#define MAX_IPS 2048

static volatile int keepSpinner = 1; // MOVIDO AQUI, ANTES DO handle_sigint

struct arp_header {
    unsigned short htype;
    unsigned short ptype;
    unsigned char  hlen;
    unsigned char  plen;
    unsigned short oper;
    unsigned char  sha[6];
    unsigned char  spa[4];
    unsigned char  tha[6];
    unsigned char  tpa[4];
};

typedef struct {
    char vendor[100];
    char ip[INET_ADDRSTRLEN];
    char mac[18];
    char hostname[NI_MAXHOST];
} Device;

Device devices[MAX_IPS];
int device_count = 0;
pthread_mutex_t lock;

// Remove aspas externas caso existam
static void strip_quotes(char *s) {
    char *start = s;
    while (*start == '"') {
        start++;
    }
    char *end = start + strlen(start) - 1;
    while (end > start && *end == '"') {
        *end = '\0';
        end--;
    }
    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }
}

// Versão robusta que só lê as 2 primeiras colunas do CSV
void get_mac_vendor(const char *mac, char *vendor, size_t vendor_size) {
    FILE *file = fopen("mac_vendors.csv", "r");
    if (!file) {
        strncpy(vendor, "Unknown", vendor_size);
        return;
    }
    char line[256];
    // MAC prefix: 00:00:XX => 8 chars
    char mac_prefix[9];
    strncpy(mac_prefix, mac, 8);
    mac_prefix[8] = '\0';

    while (fgets(line, sizeof(line), file)) {
        // Remove \n
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        // Primeira coluna (até a primeira vírgula)
        char *comma = strchr(line, ',');
        if (!comma) {
            continue;
        }
        *comma = '\0';
        char *col1 = line;      // ex: 00:00:0C
        char *rest = comma + 1; // ex: "Cisco Systems, Inc",false,MA-L,2015/11/17

        // Segunda coluna (até a próxima vírgula, se houver)
        char *comma2 = strchr(rest, ',');
        if (comma2) {
            *comma2 = '\0';
        }
        char *col2 = rest; // ex: "Cisco Systems, Inc"

        strip_quotes(col1);
        strip_quotes(col2);

        // Se col1 == mac_prefix, é o registro certo
        if (strcasecmp(mac_prefix, col1) == 0) {
            strncpy(vendor, col2, vendor_size);
            fclose(file);
            return;
        }
    }
    fclose(file);
    strncpy(vendor, "Unknown", vendor_size);
}

void save_results_to_json() {
    FILE *file = fopen("results.json", "w");
    if (!file) {
        return;
    }
    fprintf(file, "[\n");
    for (int i = 0; i < device_count; i++) {
        fprintf(file,
                "  {\"ip\": \"%s\", \"mac\": \"%s\", \"hostname\": \"%s\", \"vendor\": \"%s\"}%s\n",
                devices[i].ip,
                devices[i].mac,
                devices[i].hostname,
                devices[i].vendor,
                (i < device_count - 1) ? "," : "");
    }
    fprintf(file, "]\n");
    fclose(file);
}

void handle_sigint(int sig) {
    keepSpinner = 0;          // Para o spinner
    usleep(300000);           // Dá um tempo para remover o último char do spinner
    save_results_to_json();   // Salva resultados
    exit(0);                  // Encerra
}

static void *spinner_thread(void *arg) {
    const char spinChars[] = { '|', '/', '-', '\\' }; // ajustado
    int idx = 0;
    printf("Analyzing network: ");
    fflush(stdout);
    while (keepSpinner) {
        printf("%c", spinChars[idx]);
        fflush(stdout);
        usleep(200000);
        printf("\b");
        fflush(stdout);
        idx = (idx + 1) % 4;
    }
    return NULL;
}

static void *arp_scan(void *arg) {
    char *ip = (char*)arg;
    int sock = socket(AF_INET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        free(ip);
        return NULL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        free(ip);
        return NULL;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ARP);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        free(ip);
        return NULL;
    }

    unsigned char buffer[42];
    memset(buffer, 0, sizeof(buffer));
    struct ether_header *eh = (struct ether_header *)buffer;
    memset(eh->ether_dhost, 0xff, 6);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        free(ip);
        return NULL;
    }

    memcpy(eh->ether_shost, ifr.ifr_hwaddr.sa_data, 6);
    eh->ether_type = htons(ETHERTYPE_ARP);

    struct arp_header *arph = (struct arp_header *)(buffer + 14);
    arph->htype = htons(1);
    arph->ptype = htons(ETHERTYPE_IP);
    arph->hlen  = 6;
    arph->plen  = 4;
    arph->oper  = htons(1);
    memcpy(arph->sha, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        free(ip);
        return NULL;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(arph->spa, &sin->sin_addr.s_addr, 4);

    struct in_addr target_addr;
    inet_pton(AF_INET, ip, &target_addr);
    memcpy(arph->tpa, &target_addr.s_addr, 4);

    struct sockaddr_ll to;
    memset(&to, 0, sizeof(to));
    to.sll_family  = AF_PACKET;
    to.sll_ifindex = ifr.ifr_ifindex;
    to.sll_halen   = 6;
    memset(to.sll_addr, 0xff, 6);

    sendto(sock, buffer, 42, 0, (struct sockaddr*)&to, sizeof(to));

    struct timeval tv;
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        unsigned char recvbuf[60];
        struct sockaddr saddr;
        socklen_t saddr_len = sizeof(saddr);
        int len = recvfrom(sock, recvbuf, 60, 0, &saddr, &saddr_len);
        if (len < 0) {
            break;
        }
        struct ether_header *reh = (struct ether_header*)recvbuf;
        if (ntohs(reh->ether_type) == ETHERTYPE_ARP) {
            struct arp_header *rearph = (struct arp_header *)(recvbuf + 14);
            if (ntohs(rearph->oper) == 2 && memcmp(rearph->tpa, arph->spa, 4) == 0) {
                char macbuf[18];
                snprintf(macbuf, sizeof(macbuf),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         rearph->sha[0], rearph->sha[1], rearph->sha[2],
                         rearph->sha[3], rearph->sha[4], rearph->sha[5]);

                pthread_mutex_lock(&lock);
                if (device_count < MAX_IPS) {
                    strncpy(devices[device_count].ip, ip, sizeof(devices[device_count].ip));
                    strncpy(devices[device_count].mac, macbuf, sizeof(devices[device_count].mac));
                    get_mac_vendor(macbuf, devices[device_count].vendor, sizeof(devices[device_count].vendor));
                    strncpy(devices[device_count].hostname, "ARP", sizeof(devices[device_count].hostname));
                    device_count++;
                    printf("[+] Dispositivo encontrado: %s (MAC: %s)\n", ip, macbuf);
                }
                pthread_mutex_unlock(&lock);
                break;
            }
        }
    }

    close(sock);
    free(ip);
    return NULL;
}

int main() {
    signal(SIGINT, handle_sigint);
    pthread_mutex_init(&lock, NULL);
    pthread_t spinTh;
    pthread_create(&spinTh, NULL, spinner_thread, NULL);
    pthread_detach(spinTh);

    char base[INET_ADDRSTRLEN] = "192.168";

    pthread_t th[MAX_IPS];
    int thread_index = 0;

    for (int subnet = 72; subnet <= 79; subnet++) {
        for (int host = 1; host < 255; host++) {
            if (thread_index >= MAX_IPS) break;
            char *ip = malloc(32);
            snprintf(ip, 32, "%s.%d.%d", base, subnet, host);
            
            pthread_create(&th[thread_index], NULL, arp_scan, ip);
            pthread_detach(th[thread_index]);
            thread_index++;
        }
    }

    while (1) {
        sleep(5);
    }

    save_results_to_json();
    pthread_mutex_destroy(&lock);
    return 0;
}
