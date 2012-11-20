#include "print_arp.h"

#include <EtherCard.h>
#include "defines.h"

// parse ARP packets
String arp_print(byte *l3, unsigned int payload_len) {
  String s;
  struct arphdr *arp = (struct arphdr *) l3;
  uint16_t ar_hrd = ntohs(arp->ar_hrd);
  uint16_t ar_pro = ntohs(arp->ar_pro);
  uint8_t ar_hln = arp->ar_hln;
  uint8_t ar_pln = arp->ar_pln;
  uint16_t ar_op = ntohs(arp->ar_op);
  char ipv4str[16];
  
  s += String("ARP len=") + String(payload_len);
  s += " htype=" + String(ar_hrd);
  s += " ptype=0x" + String(ar_pro, HEX);
  s += " hlen=" + String(ar_hln);
  s += " plen=" + String(ar_pln);
  s += " oper=" + String(ar_op) + "(" + (ar_op == ARPOP_REQUEST ? "request" : ar_op == ARPOP_REPLY ? "reply" : "unknown operation") + ")";

  byte *p = arp->sha;
  s += " sender HW=0x" + hexdump(p, ar_hln);
  p += ar_hln;

  s += " sender protoaddr=";
  if (ar_pro == ETHERTYPE_IP) {
    ether.makeNetStr(ipv4str, p, 4, '.', 10);
    s += String(ipv4str);
  } else {
    s += "=0x" + hexdump(p, ar_pln);
  }
  p += ar_pln;

  if (ar_op != ARPOP_REQUEST) {
    s += " target HW=0x" + hexdump(p, ar_hln);
  }
  p += ar_hln;

  s += " target protoaddr=";
  if (ar_pro == ETHERTYPE_IP) {
    ether.makeNetStr(ipv4str, p, 4, '.', 10);
    s += String(ipv4str);
  } else {
      s += "0x" + hexdump(p, ar_pln);
  }

  return s;
}
