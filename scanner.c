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

#define MAX_IPS 256

static volatile int keepSpinner = 1;
static volatile int stopFlag = 0;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char mac[18];
} Device;

Device found[MAX_IPS];
int foundCount = 0;

pthread_mutex_t lock;

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

static void handle_sigint(int sig) {
    keepSpinner = 0;
    stopFlag = 1;
}

static void *spinner_thread(void *arg) {
    const char spinChars[] = { '|', '/', '-', '\\' };
    int idx = 0;
    printf("Analyzing network: ");
    fflush(stdout);

    while (keepSpinner) {
        printf("%c", spinChars[idx]);
        fflush(stdout);
        usleep(200000);

        // Volta 1 caractere
        printf("\b");
        fflush(stdout);

        idx = (idx + 1) % 4;
    }
    return NULL;
}

static void send_arp_request(int sock, const struct sockaddr_ll *bindAddr,
                             const unsigned char *local_mac,
                             const unsigned char *local_ip,
                             const char *target_ip)
{
    unsigned char buffer[42];
    memset(buffer, 0, sizeof(buffer));

    struct ether_header *eh = (struct ether_header *)buffer;
    memset(eh->ether_dhost, 0xff, 6); 
    memcpy(eh->ether_shost, local_mac, 6);
    eh->ether_type = htons(ETHERTYPE_ARP);

    struct arp_header *arph = (struct arp_header *)(buffer + 14);
    arph->htype = htons(1);
    arph->ptype = htons(ETHERTYPE_IP);
    arph->hlen  = 6;
    arph->plen  = 4;
    arph->oper  = htons(1); // ARP Request
    memcpy(arph->sha, local_mac, 6);
    memcpy(arph->spa, local_ip, 4);

    struct in_addr tgt;
    inet_pton(AF_INET, target_ip, &tgt);
    memcpy(arph->tpa, &tgt.s_addr, 4);

    sendto(sock, buffer, 42, 0,
           (const struct sockaddr *)bindAddr, sizeof(*bindAddr));
}

int main() {
    signal(SIGINT, handle_sigint);
    pthread_mutex_init(&lock, NULL);

    char iface[IFNAMSIZ];
    printf("Interface (ex: eth0, wlan0): ");
    scanf("%s", iface);

    char prefix[16];
    printf("Prefixo da rede (ex: 192.168.0): ");
    scanf("%s", prefix);

    // Inicia spinner
    pthread_t spin;
    pthread_create(&spin, NULL, spinner_thread, NULL);
    pthread_detach(spin);

    // Abre socket raw
    int sock = socket(AF_INET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Descobre ifindex
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sock);
        return 1;
    }

    struct sockaddr_ll bindAddr;
    memset(&bindAddr, 0, sizeof(bindAddr));
    bindAddr.sll_family   = AF_PACKET;
    bindAddr.sll_ifindex  = ifr.ifr_ifindex;
    bindAddr.sll_protocol = htons(ETH_P_ARP);
    if (bind(sock, (struct sockaddr *)&bindAddr, sizeof(bindAddr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    // MAC local
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(sock);
        return 1;
    }
    unsigned char local_mac[6];
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);

    // IP local
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        close(sock);
        return 1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    unsigned char local_ip[4];
    memcpy(local_ip, &sin->sin_addr.s_addr, 4);

    // Envia ARPs para 1..254
    for (int i = 1; i < 255; i++) {
        if (stopFlag) break;
        char ipbuf[32];
        snprintf(ipbuf, sizeof(ipbuf), "%s.%d", prefix, i);
        send_arp_request(sock, &bindAddr, local_mac, local_ip, ipbuf);
    }

    // 2s de timeout
    struct timeval tv;
    tv.tv_sec  = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Escuta respostas
    while (!stopFlag) {
        unsigned char recvbuf[60];
        struct sockaddr saddr;
        socklen_t saddr_len = sizeof(saddr);
        int len = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, &saddr, &saddr_len);
        if (len < 0) {
            // Timeout ou sinal => encerra
            break;
        }
        struct ether_header *eh = (struct ether_header *)recvbuf;
        if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
            struct arp_header *rearph = (struct arp_header *)(recvbuf + 14);
            if (ntohs(rearph->oper) == 2) { // ARP Reply
                struct in_addr raddr;
                memcpy(&raddr.s_addr, rearph->spa, 4);
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &raddr, ipstr, sizeof(ipstr));

                char macstr[18];
                snprintf(macstr, sizeof(macstr),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         rearph->sha[0], rearph->sha[1], rearph->sha[2],
                         rearph->sha[3], rearph->sha[4], rearph->sha[5]);

                pthread_mutex_lock(&lock);
                if (foundCount < MAX_IPS) {
                    strcpy(found[foundCount].ip, ipstr);
                    strcpy(found[foundCount].mac, macstr);
                    foundCount++;
                }
                pthread_mutex_unlock(&lock);

                printf("[+] %s => %s\n", ipstr, macstr);
            }
        }
    }

    keepSpinner = 0; // Para spinner
    usleep(300000);

    printf("\nDispositivos encontrados:\n");
    for (int i = 0; i < foundCount; i++) {
        printf("IP: %s  MAC: %s\n", found[i].ip, found[i].mac);
    }

    close(sock);
    return 0;
}
