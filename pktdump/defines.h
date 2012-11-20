#ifndef DEFINES_H
#define DEFINES_H

// net/ethernet.h
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86DD

// linux/if_ether.h
#define ETH_FRAME_LEN 1514
#define ETH_ALEN 6

// net/ethernet.h
struct ether_header {
  uint8_t  ether_dhost[ETH_ALEN]; 
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

// type of the function that can handle L3 layer packets
typedef String (*l3_printer)(byte *l3, unsigned int payload_len);

// Ethernet/util.h
#define htons(x) ( ((x)<<8) | (((x)>>8)&0xFF) )
#define ntohs(x) htons(x)
#define htonl(x) ( ((x)<<24 & 0xFF000000UL) | \
                   ((x)<< 8 & 0x00FF0000UL) | \
                   ((x)>> 8 & 0x0000FF00UL) | \
                   ((x)>>24 & 0x000000FFUL) )
#define ntohl(x) htonl(x)

#define LED_PIN 13

String hexdump(byte *p, unsigned int len);

#endif // DEFINES_H
