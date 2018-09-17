#include <pcap.h>
#include <stdio.h>

const int ETHERNET_HEADER_LEN = 14;
const int IP_HEADER_LEN = 20; // at least 20
const int TCP_HEADER_LEN = 20; // at least 20 
class ethernet_header{
public:
    u_char destMAC[6], srcMAC[6];
    u_short Etype;
    void printMAC(int isDest);
};    
void ethernet_header::printMAC(int isDest){ // 0 : source, 1 : dest
   u_char* mac;
   if(isDest) mac = destMAC;
   else mac = srcMAC;
   printf("%d",*mac);
   mac++;
   int len = 5;
   while(len--) printf(":%d",*(mac++));
   printf("\n");
}
class IPv4_header{
public:
    u_char Ver_IHL, DSCP_ECN;
    u_short len, Id;
    u_short Flag_Fragment;
    u_char TTL, Protocol;
    u_short checksum;
    u_int srcIP, destIP;
    u_char* option;
    u_int IHL;
    void printIP(int isDest);
};
void IPv4_header::printIP(int isDest){
    IPv4_header ipHeader;
    u_int ip;
    if(isDest) ip = destIP;
    else ip = srcIP;
    printf("%d.%d.%d.%d\n",ip>>24,((ip>>16 & 0xff)),((ip>>8)&0xff),ip&0xff);
}

class TCP_header{
public:
    u_short srcPort, destPort;
    u_int seqNumber, ackNumber;
    u_short flag, windowSize;
    u_short checksum, urgentPtr;
    u_char* option;
    u_int DataOffset;
};

void dump(const u_char* p, int len){
// parse Ethernet header
    ethernet_header ethHeader;
    if(len<ETHERNET_HEADER_LEN){
        printf("length is not enough to parse  ehternet header.\n");
        return;
    }
    for(int i = 0; i < 6; i++) ethHeader.destMAC[i] = (u_char) *(p++);
    for(int i = 0; i < 6; i++) ethHeader.srcMAC[i] = (u_char) *(p++);
    ethHeader.Etype = ((u_short) *(p++)) << 8;
    ethHeader.Etype |= (u_short) *(p++);
    printf("src  MAC Address : ");
    ethHeader.printMAC(0);
    printf("dest  MAC Address : ");
    ethHeader.printMAC(1);
    if(ethHeader.Etype != 0x0800) return;
    // parse IP header
    if(len < ETHERNET_HEADER_LEN+IP_HEADER_LEN){
        printf("length is not enough to parse ip header.\n");
        return;
    }
    IPv4_header ipHeader;
    ipHeader.Ver_IHL = (u_char) *(p++);
    ipHeader.DSCP_ECN = (u_char) *(p++);
    ipHeader.len = ((u_short) *(p++)) << 8;
    ipHeader.len |= (u_short) *(p++);
    if(ETHERNET_HEADER_LEN + ipHeader.len > len){
        printf("length is not enough to parse ip header.\n");
        return;
    }
    ipHeader.Id = ((u_short) *(p++)) << 8;
    ipHeader.Id |= (u_short) *(p++);
    ipHeader.Flag_Fragment =  ((u_short) *(p++)) << 8;
    ipHeader.Flag_Fragment |= (u_short) *(p++);
    ipHeader.TTL = (u_char) *(p++);
    ipHeader.Protocol = (u_char) *(p++);
    ipHeader.checksum =  ((u_short) *(p++)) << 8;
    ipHeader.checksum |= (u_short) *(p++);
    ipHeader.srcIP =  ((u_int) *(p++)) << 24;
    ipHeader.srcIP |=  ((u_int) *(p++)) << 16;
    ipHeader.srcIP |=  ((u_int) *(p++)) << 8;
    ipHeader.srcIP |=  (u_int) *(p++);
    ipHeader.destIP =  ((u_int) *(p++)) << 24;
    ipHeader.destIP |=  ((u_int) *(p++)) << 16;
    ipHeader.destIP |=  ((u_int) *(p++)) << 8;
    ipHeader.destIP |=  (u_int) *(p++);
    ipHeader.IHL = (ipHeader.Ver_IHL&0xf);
    if(ipHeader.IHL < 5){
        printf("wrong IHL value(%d) in IP header\n", ipHeader.IHL);
        return;
    }
    else if(ipHeader.IHL == 5){
        ipHeader.option = NULL;
    }
    else{
        if(len < ETHERNET_HEADER_LEN+(ipHeader.IHL<<2)){
            printf("ipHeader.IHL : %d\n",ipHeader.IHL);
            printf("length is not enough to parse ip header.\n");
            return;
        }
        ipHeader.option = new u_char[(ipHeader.IHL-5)<<2];
        for(int i = 0; i < ((ipHeader.IHL-5)<<2); i++)
            ipHeader.option[i] = (u_char) *(p++);
    }
    printf("src IP : ");
    ipHeader.printIP(0);
    printf("dest IP : ");
    ipHeader.printIP(1);
    if(ipHeader.Protocol != 0x06) return;
    // parse TCP header
    if(len < ETHERNET_HEADER_LEN+(ipHeader.IHL<<2)+TCP_HEADER_LEN){
        printf("length is not enough to parse tcp header.\n");
        return;
    }
    TCP_header tcpHeader;
    tcpHeader.srcPort =  ((u_short) *(p++)) << 8;
    tcpHeader.srcPort |=  (u_short) *(p++);
    tcpHeader.destPort =  ((u_short) *(p++)) << 8;
    tcpHeader.destPort |=  (u_short) *(p++);
    tcpHeader.seqNumber =  ((u_int) *(p++)) << 24;
    tcpHeader.seqNumber |=  ((u_int) *(p++)) << 16;
    tcpHeader.seqNumber |=  ((u_int) *(p++)) << 8;
    tcpHeader.seqNumber |=  (u_int) *(p++);
    tcpHeader.ackNumber =  ((u_int) *(p++)) << 24;
    tcpHeader.ackNumber |=  ((u_int) *(p++)) << 16;
    tcpHeader.ackNumber |=  ((u_int) *(p++)) << 8;
    tcpHeader.ackNumber |=  (u_int) *(p++);
    tcpHeader.flag = ((u_short) *(p++)) << 8;
    tcpHeader.flag |= (u_short) *(p++);
    tcpHeader.DataOffset = tcpHeader.flag >> 12;
    tcpHeader.windowSize =  ((u_short) *(p++)) << 8;
    tcpHeader.windowSize |=  (u_short) *(p++);
    tcpHeader.checksum =  ((u_short) *(p++)) << 8;
    tcpHeader.checksum |=  (u_short) *(p++);
    tcpHeader.urgentPtr =  ((u_short) *(p++)) << 8;
    tcpHeader.urgentPtr |=  (u_short) *(p++);
    if(tcpHeader.DataOffset < 5){
        printf("wrong DataOffset value(%d) in TCP header\n",tcpHeader.DataOffset);
        return;
    }        
    else if(tcpHeader.DataOffset == 5){
        tcpHeader.option = NULL;
    }
    else{
        if(len < ETHERNET_HEADER_LEN+(ipHeader.IHL<<2)+(tcpHeader.DataOffset<<2)){
            printf("length is not enough to parse tcp header.\n");
            return;
        }
        tcpHeader.option = new u_char[((tcpHeader.DataOffset-5)<<2)];
        for(int i = 0; i < ((tcpHeader.DataOffset-5)<<2); i++)
            tcpHeader.option[i] = (u_char) *(p++);
    }
    printf("src Port : %d\n",tcpHeader.srcPort);
    printf("dest Port : %d\n",tcpHeader.destPort);
    int dataLen = ipHeader.len - (ipHeader.IHL<<2) - (tcpHeader.DataOffset<<2);
    if(dataLen == 0) return;
    printf("---------hex data---------\n");
    int printlen = dataLen > 32 ? 32 : dataLen;
    for(int i = 0; i < printlen; i++){
        printf("%02x ", *(p++));
        if(i==15) printf("\n");
    }
    printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    dump(packet, header->caplen);
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
