#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct ethernet_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct ip_hdr {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragmentoffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_reserved;
    uint8_t cwr_fin;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

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

void p_ip(uint32_t ip) {
    unsigned char* p = (unsigned char*)&ip;
    printf("%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

void p_payload(const u_char* payload, int len) {
    printf("payload bytes: %d ", len);
    for (int i = 0; i < len && i < 20; i++)
        printf("%02x ", payload[i]);
    printf("\n");
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
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        const struct ethernet_header* eth = (const struct ethernet_header*)packet;
        if (ntohs(eth->eth_type) != 0x0800) continue;

        const struct ip_hdr* ip = (const struct ip_hdr*)(packet + sizeof(struct ethernet_header));
        if (ip->protocol != 6) continue;

        int ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
        int ip_total_len = ntohs(ip->total_length);

        const struct tcp_hdr* tcp = (const struct tcp_hdr*)((const u_char*)ip + ip_hdr_len);
        int tcp_hdr_len = ((tcp->data_reserved >> 4) & 0x0F) * 4;

        const u_char* payload = (const u_char*)tcp + tcp_hdr_len;
        int payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

        printf("\n");

        printf("ethernet src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
               eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);

        printf("ethernet dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
               eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);

        printf("ip src : "); p_ip(ip->src_ip); printf("\n");
        printf("ip dst : "); p_ip(ip->dst_ip); printf("\n");

        printf("tcp src port : %u\n", ntohs(tcp->src_port));
        printf("tcp dst port : %u\n", ntohs(tcp->dst_port));

        if (payload_len > 0)
            p_payload(payload, payload_len);
        else
            printf("payload: X\n");
    }

    pcap_close(pcap);
    return 0;
}
