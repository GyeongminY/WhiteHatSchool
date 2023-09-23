#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>


/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl : 4, //IP header length
        iph_ver : 4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

/* Structure of a TCP header */
struct tcpheader {
    unsigned short tcp_source_port;
    unsigned short tcp_dest_port;
    unsigned int tcp_seqno;
    unsigned int tcp_ackno;
    unsigned int tcp_res1 : 4, /*little-endian*/
        tcp_hlen : 4, //TCP header length is 4bits
        tcp_fin : 1,
        tcp_syn : 1,
        tcp_rst : 1,
        tcp_psh : 1,
        tcp_ack : 1,
        tcp_urg : 1,
        tcp_res2 : 2;
    unsigned short tcp_winsize;
    unsigned short tcp_cksum;
    unsigned short tcp_urgent;
};

void got_packet(u_char* args, const struct pcap_pkthdr* header,
    const u_char* packet)
{
    const struct ethheader* eth = (struct ethheader*)packet;

    //print Ethernet Header
    printf("Ethernet Header (dst address): %s\n", ether_ntoa((const struct ether_addr *)eth->ether_dhost));
    printf("Ethernet Header (src address): %s\n", ether_ntoa((const struct ether_addr *)eth->ether_shost));

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader* ip = (struct ipheader*)
            (packet + sizeof(struct ethheader));
        //print IP Header
        printf("IP Header (src ip): %s\n", inet_ntoa(ip->iph_sourceip));
        printf("IP Header (dst ip): %s\n", inet_ntoa(ip->iph_destip));

        //tcphdr = (struct tcphdr*)((char*)packet + 20);
        struct tcpheader* tcp = (struct tcpheader*)(packet + 14 + (ip->iph_ihl) * 4);
        //print TCP Header
        printf("TCP Header (src port): %d\n", ntohs(tcp->tcp_source_port));
        printf("TCP Header (dst port): %d\n", ntohs(tcp->tcp_dest_port));

        //print Message
        printf("Just do it!\n");

        /* determine protocol */
        switch (ip->iph_protocol) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
        }
    }
}

int main()
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);   //Close the handle
    return 0;
}
