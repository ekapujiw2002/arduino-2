// linux/if_ether.h
#define ETH_FRAME_LEN 1514
#define ETH_ALEN 6

// net/ethernet.h
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86DD

// net/ethernet.h
struct ether_header {
  uint8_t  ether_dhost[ETH_ALEN]; 
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

// net/if_arp.h
struct arphdr {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
    byte sha[0];
};
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

// netinet/in.h
enum {
  IPPROTO_ICMP = 1,
  IPPROTO_TCP = 6,
  IPPROTO_UDP = 17,
};

// netinet/ip.h
struct iphdr {
  unsigned int ihl:4;
  unsigned int version:4;
//  uint8_t ihl_version;
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  /* The options start here. */
};

struct icmphdr {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  union {
    struct {
      uint16_t id;
      uint16_t sequence;
    } echo;
    uint32_t gateway;
    struct {
      uint16_t __unused;
      uint16_t mtu;
    } frag;
  } un;
};

#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8

// type of the function that can handle L3 layer packets
typedef String (*l3_printer)(byte *l3, unsigned int payload_len);

extern String ip_print(byte *l3, unsigned int payload_len);
extern String arp_print(byte *l3, unsigned int payload_len);

static struct {
  uint16_t ether_proto;
  l3_printer printer;
} ether_protocol_handlers[] = {
 { ETHERTYPE_IP, ip_print },
 { ETHERTYPE_ARP, arp_print },
 { ETHERTYPE_VLAN, NULL },
 { ETHERTYPE_IPV6, NULL },
 { 0, NULL }
};

// Ethernet/util.h
#define htons(x) ( ((x)<<8) | (((x)>>8)&0xFF) )
#define ntohs(x) htons(x)
#define htonl(x) ( ((x)<<24 & 0xFF000000UL) | \
                   ((x)<< 8 & 0x00FF0000UL) | \
                   ((x)>> 8 & 0x0000FF00UL) | \
                   ((x)>>24 & 0x000000FFUL) )
#define ntohl(x) htonl(x)

#define LED_PIN 13
