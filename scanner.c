#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <signal.h>

#define MAX_IPS 256

typedef struct {
    char vendor[100];
    char ip[INET_ADDRSTRLEN];
    char mac[18];
    char hostname[NI_MAXHOST];
} Device;

Device devices[MAX_IPS];
int device_count = 0;
pthread_mutex_t lock;

void get_mac_vendor(const char *mac, char *vendor, size_t vendor_size) {
    char prefix[9];
    snprintf(prefix, sizeof(prefix), "%2.2s:%2.2s:%2.2s", mac, mac + 3, mac + 6);
    FILE *f = fopen("mac_vendors.csv", "r");
    if (!f) {
        strncpy(vendor, "Unknown", vendor_size);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char entry[10], vend[100];
        if (sscanf(line, "%9[^,],\"%99[^\"]\"", entry, vend) == 2) {
            if (strcasecmp(prefix, entry) == 0) {
                strncpy(vendor, vend, vendor_size);
                fclose(f);
                return;
            }
        }
    }
    fclose(f);
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
    save_results_to_json();
    exit(0);
}

void *scan_ip(void *arg) {
    char *ip = (char *)arg;
    struct sockaddr_in sa;
    char host[NI_MAXHOST];
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
        pthread_mutex_lock(&lock);
        strcpy(devices[device_count].ip, ip);
        strcpy(devices[device_count].hostname, host);
        device_count++;
        pthread_mutex_unlock(&lock);
        printf("Device: %s (%s)\n", host, ip);
    } else {
        pthread_mutex_lock(&lock);
        strcpy(devices[device_count].ip, ip);
        strcpy(devices[device_count].hostname, "Unknown");
        device_count++;
        pthread_mutex_unlock(&lock);
        printf("Device: Unknown (%s)\n", ip);
    }
    free(arg);
    return NULL;
}

void capture_arp_packets() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return;
    }
    for (device = alldevs; device != NULL; device = device->next) {
        pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            continue;
        }
        struct pcap_pkthdr header;
        const u_char *packet;
        while ((packet = pcap_next(handle, &header)) != NULL) {
            struct ether_header *eth_hdr = (struct ether_header *)packet;
            if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
                struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
                struct in_addr sender_addr;
                memcpy(&sender_addr, arp_hdr->arp_spa, sizeof(struct in_addr));
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sender_addr, sender_ip, INET_ADDRSTRLEN);
                pthread_mutex_lock(&lock);
                if (device_count < MAX_IPS) {
                    strcpy(devices[device_count].ip, sender_ip);
                    sprintf(devices[device_count].mac,
                            "%02x:%02x:%02x:%02x:%02x:%02x",
                            arp_hdr->arp_sha[0],
                            arp_hdr->arp_sha[1],
                            arp_hdr->arp_sha[2],
                            arp_hdr->arp_sha[3],
                            arp_hdr->arp_sha[4],
                            arp_hdr->arp_sha[5]);
                    strcpy(devices[device_count].hostname, "Detected via ARP");
                    get_mac_vendor(devices[device_count].mac,
                                   devices[device_count].vendor,
                                   sizeof(devices[device_count].vendor));
                    device_count++;
                }
                pthread_mutex_unlock(&lock);
                printf("[ARP] Device found: %s (%s)\n", sender_ip, devices[device_count - 1].mac);
            }
        }
        pcap_close(handle);
    }
    pcap_freealldevs(alldevs);
}

int main() {
    char interface_name[IFNAMSIZ];
    printf("Digite a interface de rede (ex: wlan0, eth0): ");
    scanf("%s", interface_name);
    pthread_mutex_init(&lock, NULL);
    signal(SIGINT, handle_sigint);
    printf("Starting ARP monitoring...\n");
    capture_arp_packets();
    save_results_to_json();
    pthread_mutex_destroy(&lock);
    return 0;
}
