// linux/if_ether.h
#define ETH_FRAME_LEN 1514

// net/ethernet.h
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

static struct {
  uint16_t ether_proto;
  char *str;
} ether_protocol_str[] = {
 { ETHERTYPE_IP, "IP" },
 { ETHERTYPE_ARP, "ARP" },
 { ETHERTYPE_IPV6, "IPv6" },
 { 0, NULL }
};

