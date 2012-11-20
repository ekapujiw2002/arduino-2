#include "print_ip.h"

#include <EtherCard.h>
#include "defines.h"

// print the transport protocol in the IP packet payload
String ip_protocol_print(byte *l4, unsigned int payload_len, uint8_t protocol) {
  String s;

  switch (protocol) {
      case IPPROTO_ICMP: {
        struct icmphdr *icmp = (struct icmphdr *) l4;
        s += ", ICMP len=" + String(payload_len) + " type=" + String(icmp->type) + " code=" + String(icmp->code) + " checksum=" + String(icmp->checksum);
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY)
          s += ", echo " + String((icmp->type == ICMP_ECHO ? "request" : "reply")) +
               " id=" + String(ntohs(icmp->un.echo.id)) + " seq=" +
               String(ntohs(icmp->un.echo.sequence)) + " datalen=" +
               String(payload_len-sizeof(struct icmphdr));
        break;
      }
      default: {
        s += ", L4 len=" + String(payload_len);
        break;
      }
  }
  return s;  
}

// parse IPv4 packets
String ip_print(byte *l3, unsigned int payload_len) {
  String s;
  struct iphdr *ip = (struct iphdr *) l3;

  s += String("IP ");

  //char str[200];
  //sprintf(str, "<len=%u>",ip->tot_len); 
  //s += str;
  if ((payload_len < sizeof(struct iphdr)) || (payload_len < (ip->ihl << 2)) ) {
    s += "[truncated IP]";
    return s;
  }
  s += "ver=" + String(ip->version);
  s += " hl=" + String(ip->ihl << 2);
  s += " TOS=" + String(ip->tos); // MASK ?, TODO DSCP/ECN
  s += " totlen=" + String(ntohs(ip->tot_len));
  s += " ID=" + String(ntohs(ip->id));
  s += " flags=" + String(ntohs(ip->frag_off) >> 13, BIN) + 'b';
  s += " fragoff=" + String(ntohs(ip->frag_off) & 0x1FFF);
  s += " ttl=" + String(ip->ttl);
  s += " protocol=" + String(ip->protocol);
  s += " csum=0x" + String(ntohs(ip->check), HEX);
  char ipv4str[16];
  ether.makeNetStr(ipv4str, (byte *)&(ip->saddr), 4, '.', 10);
  s += " saddr=";
  s += ipv4str;
  ether.makeNetStr(ipv4str, (byte *)&(ip->daddr), 4, '.', 10);
  s += " daddr=";
  s += ipv4str;

  // check for truncated L4 payload
  if (payload_len < ntohs(ip->tot_len)) {
    s += ", [truncated by " + String((ntohs(ip->tot_len) - payload_len - (ip->ihl << 2))) + " bytes";
    return s;
  }

  // controller returns always minimum of 60 byte frames (see sections 5.1, 5.1.6, and
  // ENC28J60::packetReceive seems to remove the four octet CRC) so after checks
  // we set payload length to be the total length field of the IP header decreased
  // by the header length
  payload_len = ntohs(ip->tot_len) - (ip->ihl << 2);
//  payload_len -= ip->ihl << 2;
  //s += ", L4 len=" + String(payload_len);
  if (payload_len > 0) {
    // if there are any L4 payload left, parse it
    s += ip_protocol_print((byte *)ip + (ip->ihl << 2), payload_len, ip->protocol);
  }
  return s;
}
