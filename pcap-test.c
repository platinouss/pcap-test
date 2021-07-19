#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <stdint.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void pkt_print(struct libnet_ethernet_hdr* ethernet, struct libnet_ipv4_hdr* ip,
    struct libnet_tcp_hdr* tcp, const u_char* payload, int payload_len) {

    printf("Destination Ethernet Address: ");
    for (int i = 0; i < 6; i++) {
        if (i != 5)
            printf("%02x:", ethernet->ether_dhost[i]);
        else
            printf("%02x\n", ethernet->ether_dhost[i]);
    }

    printf("Sources Ethernet Address: ");
    for (int i = 0; i < 6; i++) {
        if (i != 5)
            printf("%02x:", ethernet->ether_shost[i]);
        else
            printf("%02x\n", ethernet->ether_shost[i]);
    }

    printf("Source Address: %s\n", inet_ntoa(ip->ip_src));       //eth = (struct libnet_ethernet_hdr *) packet;
    printf("Destination Address: %s\n", inet_ntoa(ip->ip_dst));
    printf("Source Port: %d\n", ntohs(tcp->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp->th_dport));
    printf("Payload(Data): ");
    if (payload_len > 0) {
        for(int k=0; k<8; k++)
            printf("%02x ", payload[k]);
    }
    else
        printf("-No Data-");
    printf("\n--------------------------------\n");

}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

   while (true) {
        struct pcap_pkthdr* header;
        struct libnet_ethernet_hdr* ethernet;
        struct libnet_ipv4_hdr* ip;
        struct libnet_tcp_hdr* tcp;
        const u_char* packet = 0;
        const u_char* payload = 0;
        uint16_t payload_len;
        uint16_t protocol;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        ethernet = (struct libnet_ethernet_hdr *)packet;
        ip = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        tcp = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr)
                    + sizeof(struct libnet_ipv4_hdr));
        payload = (u_char *)(packet + sizeof(struct libnet_ethernet_hdr)
                             + sizeof(struct libnet_ipv4_hdr) + 20);
        payload_len = (ntohs(ip->ip_len) - sizeof(struct libnet_ipv4_hdr) - 20);


        protocol = ip->ip_p;
        if(protocol == 6)
            pkt_print(ethernet, ip, tcp, payload, payload_len);
    }

    pcap_close(pcap);
}
