#ifndef PRINT_ARP_H
#define PRINT_ARP_H

#include <Arduino.h>

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

String arp_print(byte *l3, unsigned int payload_len);

#endif // PRINT_ARP_H
