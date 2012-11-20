#ifndef PRINT_IP_H
#define PRINT_IP_H

#include <Arduino.h>

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

String ip_print(byte *l3, unsigned int payload_len);

#endif // PRINT_IP_H
