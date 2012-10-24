// linux/if_ether.h
#define ETH_FRAME_LEN 1514

// net/ethernet.h
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86DD

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

// type of the function that can handle L3 layer packets
typedef String (*l3_printer)(byte *l3, unsigned int payload_len);
                                 
extern String ip_print(byte *l3, unsigned int payload_len);

static struct {
  uint16_t ether_proto;
  l3_printer printer;
} ether_protocol_handlers[] = {
 { ETHERTYPE_IP, ip_print },
 { ETHERTYPE_ARP, NULL },
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
