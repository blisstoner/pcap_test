#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>

const int ETHERNET_HEADER_LEN = 14;
const int IP_HEADER_LEN = 20;   // at least 20
const int TCP_HEADER_LEN = 20;  // at least 20

void print_mac(uint8_t *addr) {  // 0 : source, 1 : dest
  for (int i = 0; i < 6; i++) {
    printf("%02x", *(addr++));
    if (i != 5) printf(":");
  }
  printf("\n");
}
void print_ip(uint32_t ip) {
  printf("%d.%d.%d.%d\n", ip >> 24, ((ip >> 16 & 0xff)), ((ip >> 8) & 0xff),
         ip & 0xff);
}
void dump(const uint8_t *p, int len) {
  // parse Ethernet header
  libnet_ethernet_hdr ethHeader;
  if (len < ETHERNET_HEADER_LEN) {
    printf("length is not enough to parse ehternet header.\n");
    return;
  }
  for (int i = 0; i < 6; i++) ethHeader.ether_dhost[i] = (uint8_t) * (p++);
  for (int i = 0; i < 6; i++) ethHeader.ether_shost[i] = (uint8_t) * (p++);
  ethHeader.ether_type = ((uint16_t) * (p++)) << 8;
  ethHeader.ether_type |= (uint16_t) * (p++);
  printf("src  MAC Address : ");
  print_mac(ethHeader.ether_shost);
  printf("dest  MAC Address : ");
  print_mac(ethHeader.ether_dhost);
  if (ethHeader.ether_type != ETHERTYPE_IP) return;
  // parse IP header
  if (len < ETHERNET_HEADER_LEN + IP_HEADER_LEN) {
    printf("length is not enough to parse ip header.\n");
    return;
  }
  libnet_ipv4_hdr ipHeader;
  ipHeader.ip_v = (uint8_t)((*p) >> 4);
  ipHeader.ip_hl = (uint8_t)((*(p++) & 0xf));
  ipHeader.ip_tos = (uint8_t) * (p++);
  ipHeader.ip_len = ((uint16_t) * (p++)) << 8;
  ipHeader.ip_len |= (uint16_t) * (p++);
  if (ETHERNET_HEADER_LEN + ipHeader.ip_len > len) {
    printf("length is not enough to parse ip header.\n");
    return;
  }
  ipHeader.ip_id = ((uint16_t) * (p++)) << 8;
  ipHeader.ip_id |= (uint16_t) * (p++);
  ipHeader.ip_off = ((uint16_t) * (p++)) << 8;
  ipHeader.ip_off |= (uint16_t) * (p++);
  ipHeader.ip_ttl = (uint8_t) * (p++);
  ipHeader.ip_p = (uint8_t) * (p++);
  ipHeader.ip_sum = ((uint16_t) * (p++)) << 8;
  ipHeader.ip_sum |= (uint16_t) * (p++);
  ipHeader.ip_src.s_addr = ((uint32_t) * (p++)) << 24;
  ipHeader.ip_src.s_addr |= ((uint32_t) * (p++)) << 16;
  ipHeader.ip_src.s_addr |= ((uint32_t) * (p++)) << 8;
  ipHeader.ip_src.s_addr |= (uint32_t) * (p++);
  ipHeader.ip_dst.s_addr = ((uint32_t) * (p++)) << 24;
  ipHeader.ip_dst.s_addr |= ((uint32_t) * (p++)) << 16;
  ipHeader.ip_dst.s_addr |= ((uint32_t) * (p++)) << 8;
  ipHeader.ip_dst.s_addr |= (uint32_t) * (p++);
  if (ipHeader.ip_hl < 5) {
    printf("wrong IHL value(%d) in IP header\n", ipHeader.ip_hl);
    return;
  }
  if (ipHeader.ip_hl > 5) {
    uint32_t option_len = (ipHeader.ip_hl - 5) << 2;
    if (len < ETHERNET_HEADER_LEN + option_len) {
      printf("length is not enough to parse ip header.\n");
      return;
    }
    uint8_t ip_option[option_len];
    for (int i = 0; i < option_len; i++) ip_option[i] = (uint8_t) * (p++);
  }
  printf("src IP : ");
  print_ip(ipHeader.ip_src.s_addr);
  printf("dest IP : ");
  print_ip(ipHeader.ip_dst.s_addr);
  if (ipHeader.ip_p != IPPROTO_TCP) return;
  // parse TCP header
  if (len < ETHERNET_HEADER_LEN + ((int)ipHeader.ip_hl << 2) + TCP_HEADER_LEN) {
    printf("length is not enough to parse tcp header.\n");
    return;
  }
  libnet_tcp_hdr tcpHeader;
  tcpHeader.th_sport = ((uint16_t) * (p++)) << 8;
  tcpHeader.th_sport |= (uint16_t) * (p++);
  tcpHeader.th_dport = ((uint16_t) * (p++)) << 8;
  tcpHeader.th_dport |= (uint16_t) * (p++);
  tcpHeader.th_seq = ((uint32_t) * (p++)) << 24;
  tcpHeader.th_seq |= ((uint32_t) * (p++)) << 16;
  tcpHeader.th_seq |= ((uint32_t) * (p++)) << 8;
  tcpHeader.th_seq |= (uint32_t) * (p++);
  tcpHeader.th_ack = ((uint32_t) * (p++)) << 24;
  tcpHeader.th_ack |= ((uint32_t) * (p++)) << 16;
  tcpHeader.th_ack |= ((uint32_t) * (p++)) << 8;
  tcpHeader.th_ack |= (uint32_t) * (p++);
  tcpHeader.th_off = (uint8_t)((*p) >> 4);
  tcpHeader.th_x2 = (uint8_t)((*(p++)) & 0xf);
  tcpHeader.th_flags = (uint8_t) * (p++);
  tcpHeader.th_win = ((uint16_t) * (p++)) << 8;
  tcpHeader.th_win |= (uint16_t) * (p++);
  tcpHeader.th_sum = ((uint16_t) * (p++)) << 8;
  tcpHeader.th_sum |= (uint16_t) * (p++);
  tcpHeader.th_urp = ((uint16_t) * (p++)) << 8;
  tcpHeader.th_urp |= (uint16_t) * (p++);
  if (tcpHeader.th_off < 5) {
    printf("wrong DataOffset value(%d) in TCP header\n", tcpHeader.th_off);
    return;
  }
  if (tcpHeader.th_off > 5) {
    if (len < ETHERNET_HEADER_LEN + ((int)ipHeader.ip_hl << 2) +
                  ((int)tcpHeader.th_off << 2)) {
      printf("length is not enough to parse tcp header.\n");
      return;
    }
    uint32_t option_len = (tcpHeader.th_off - 5) << 2;
    uint8_t tcp_option[option_len];
    for (int i = 0; i < option_len; i++) tcp_option[i] = (uint8_t) * (p++);
  }
  printf("src Port : %d\n", tcpHeader.th_sport);
  printf("dest Port : %d\n", tcpHeader.th_dport);
  int dataLen = ipHeader.ip_len - ((int)ipHeader.ip_hl << 2) -
                ((int)tcpHeader.th_off << 2);
  if (dataLen == 0) return;
  printf("---------hex data---------\n");
  int printlen = dataLen > 32 ? 32 : dataLen;
  for (int i = 0; i < printlen; i++) {
    printf("%02x ", *(p++));
    if (i == 15) printf("\n");
  }
  printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char *dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  //pcap_t *handle = pcap_open_offline("tcp-port-80-test.gilgil.pcap", errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (1) {
    struct pcap_pkthdr *header;
    const uint8_t *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    dump(packet, header->caplen);
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
