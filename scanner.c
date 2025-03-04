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

#define MAX_IPS 256

// Estrutura para armazenar informações dos dispositivos
typedef struct {
    char ip[INET_ADDRSTRLEN];
    char mac[18];
    char hostname[NI_MAXHOST];
} Device;

Device devices[MAX_IPS];
int device_count = 0;
pthread_mutex_t lock;

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

void get_local_network(char *base_ip) {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            strcpy(base_ip, host);
            break;
        }
    }
    
    freeifaddrs(ifaddr);
}

void capture_arp_packets() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Erro ao encontrar dispositivos: %s\n", errbuf);
        return;
    }
    
    for (device = alldevs; device != NULL; device = device->next) {
        printf("Monitorando: %s\n", device->name);
        pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
        
        if (handle == NULL) {
            fprintf(stderr, "Erro ao abrir dispositivo %s: %s\n", device->name, errbuf);
            continue;
        }
        
        struct pcap_pkthdr header;
        const u_char *packet;
        while ((packet = pcap_next(handle, &header)) != NULL) {
            struct ether_header *eth_hdr = (struct ether_header *)packet;
            if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
                struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip, INET_ADDRSTRLEN);
                
                pthread_mutex_lock(&lock);
                strcpy(devices[device_count].ip, sender_ip);
                sprintf(devices[device_count].mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                        arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2],
                        arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5]);
                strcpy(devices[device_count].hostname, "Detected via ARP");
                device_count++;
                pthread_mutex_unlock(&lock);
                printf("[ARP] Device found: %s (%s)\n", devices[device_count - 1].ip, devices[device_count - 1].mac);
            }
        }
        
        pcap_close(handle);
    }
    pcap_freealldevs(alldevs);
}

int main() {
    char base_ip[INET_ADDRSTRLEN];
    get_local_network(base_ip);
    
    printf("Scanning network: %s.0/24\n", base_ip);
    
    pthread_t threads[MAX_IPS];
    int i;
    pthread_mutex_init(&lock, NULL);
    
    for (i = 1; i < 255; i++) {
    char *ip = malloc(INET_ADDRSTRLEN + 4);
    if (ip == NULL) {
        perror("Erro ao alocar memória para IP");
        exit(EXIT_FAILURE);
    }
    
    if (ip == NULL) {
        perror("Erro ao alocar memória para IP");
        exit(EXIT_FAILURE);
    }
    
    if (ip == NULL) {
        perror("Erro ao alocar memória para IP");
        exit(EXIT_FAILURE);
    }
     // Aloca memória para o IP
    if (ip == NULL) {
        perror("Erro ao alocar memória para IP");
        exit(EXIT_FAILURE);
    }
        
         // INET_ADDRSTRLEN (16) + espaço extra para ".xxx"
snprintf(ip, INET_ADDRSTRLEN + 4, "%s.%d", base_ip, i);
    pthread_create(&threads[i], NULL, scan_ip, ip);
    }
    
    for (i = 1; i < 255; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("Starting ARP monitoring...\n");
    capture_arp_packets();
    
    pthread_mutex_destroy(&lock);
    return 0;
}
