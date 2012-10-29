/*
 * Mini tcpdump style application for Arduino and ENC28J60 Ethernet controller.
 * Uses the EtherCard library. This application shows information on received
 * Ethernet frames on Serial and/or LCD.
 *
 * Currently implemented (more or less):
 * -Ethernet header
 *  -ARP header
 *  -IPv4 header
 *   -ICMP header
 *    -ECHO reply/request
 */

// TODO:
// more length validation checks
// more handlers for L3/L4 protocols
// code commenting and cleanup
// generalize LCD code for other than 16x2 displays
// IP: check DSCP/ECN flags

#define prg_version "v0.6"

#include <EtherCard.h>
#include "defines.h"

// currently supports well 16x2 LCD screen
#define HAVE_LCD
#ifdef HAVE_LCD
 #include <LiquidCrystal.h>
 LiquidCrystal lcd(8, 13, 9, 4, 5, 6, 7); // this works for me, change for your case

 #define LCD_COLS 16
 #define LCD_ROWS 2
#endif

static byte mymac[] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
static byte myip[] = { 192,168,20,123 }; // not needed ?
//static byte myip[] = { 10,0,0,111}; // not needed ?

#define CAPTURE_SIZE (ETH_FRAME_LEN+1)
//#define CAPTURE_SIZE (14+20+1) // to test truncated frames
byte Ethernet::buffer[CAPTURE_SIZE];

// print string s on Serial if print_serial is true, print s also on LCD if print_lcd is true
void printstr(String s, boolean print_serial, boolean print_lcd = 0) {
#ifdef HAVE_LCD
  if (print_lcd) {
    lcd.clear();
    lcd.print(s.substring(0, LCD_COLS+1));
    if (s.length() > LCD_COLS) {
      lcd.setCursor(0, 1);
      lcd.print(s.substring(LCD_COLS, LCD_COLS*2));
    }
  }
#endif
  if (print_serial)
    Serial.println(s);
}

// parse ARP packets
String arp_print(byte *l3, unsigned int payload_len) {
  String s;
  struct arphdr *arp = (struct arphdr *) l3;
  uint16_t ar_hrd = ntohs(arp->ar_hrd);
  uint16_t ar_pro = ntohs(arp->ar_pro);
  uint8_t ar_hln = arp->ar_hln;
  uint8_t ar_pln = arp->ar_pln;
  uint16_t ar_op = ntohs(arp->ar_op);
  int i;
  
  s += String("ARP ");
  s += "htype=" + String(ar_hrd);
  s += " ptype=0x" + String(ar_pro, HEX);
  s += " hlen=" + String(ar_hln);
  s += " plen=" + String(ar_pln);
  s += " oper=" + String(ar_op) + "(" + (ar_op == ARPOP_REQUEST ? "request" : ar_op == ARPOP_REPLY ? "reply" : "unknown operation") + ")";

  byte *p = arp->sha;
  s += " sender HW=0x";
  for (i = 0; i < ar_hln; i++, p++) {
    if (*p <= 0xf) s += '0';
    s += String(*p, HEX);
  }

  s += " sender protoaddr=0x";
  for (i = 0; i < ar_pln; i++, p++) {
    if (*p <= 0xf) s += '0';
    s += String(*p, HEX);
  }

  if (ar_op != ARPOP_REQUEST) {
    s += " target HW=0x";
    for (i = 0; i < ar_hln; i++, p++) {
      if (*p <= 0xf) s += '0';
      s += String(*p, HEX);
    }
  } else {
    p += ar_hln;
  }
  
  s += " target protoaddr=0x";
  for (i = 0; i < ar_pln; i++, p++) {
    if (*p <= 0xf) s += '0';
    s += String(*p, HEX);
  }

  return s;
}

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

unsigned long int recvd_frames = 0;

// dump Ethernet header and parse higher layers
String dump_frame(byte *frame, word frame_len) {
  String s;
  struct ether_header *eth = (struct ether_header *) frame;
  int i;
  byte *p;

  s = '#' + String(recvd_frames) + ' ';

  if (frame_len < ETH_HEADER_LEN) {
     s += String("short frame, frame length=") + frame_len;
     return s;
  }

  p = eth->ether_shost;
  for (i = 0; i < ETH_ALEN; i++) {
    if (*(p + i) <= 0xf) s += '0';
    s += String(*(p + i), HEX);
    if (i != ETH_ALEN-1) s += ':';
  }
  s += '>';
  p = eth->ether_dhost;
  for (i = 0; i < ETH_ALEN; i++) {
    if (*(p + i) <= 0xf) s += '0';
    s += String(*(p + i), HEX);
    if (i != ETH_ALEN-1) s += ':';
  }

  s += " len=" + String(frame_len) + ", ";

  uint16_t ethproto = ntohs(eth->ether_type);

  for (i = 0; ether_protocol_handlers[i].ether_proto; i++) {
    if (ether_protocol_handlers[i].ether_proto == ethproto) {
      if (ether_protocol_handlers[i].printer) {
        // call L3 level protocol handler if it is defined
        s += ether_protocol_handlers[i].printer(frame + ETH_HEADER_LEN, frame_len - ETH_HEADER_LEN);
        return s;
      }
    }
  }
 
  // unknown protocol, print the protocol number and its payload length
  s += "protocol 0x" + String(ethproto, HEX) + " len=" + String(frame_len - ETH_HEADER_LEN);

  return s;
}

void switch_led(void) {
  static int led = HIGH;
  // switch LED state when a frame was received
  digitalWrite(LED_PIN, led);
  led = led == HIGH ? LOW : HIGH;
}

void setup () {
  Serial.begin(9600);
#ifdef HAVE_LCD
  lcd.begin(LCD_COLS, LCD_ROWS);
#endif
  pinMode(LED_PIN, OUTPUT);
  while (true) {
    uint8_t rev = ether.begin(CAPTURE_SIZE, mymac);
    if (rev == 0) {
      printstr("Failed to access Ethernet controller", true, true);
      delay(1000);
    } else {
      printstr("pktdump " prg_version ", controller revision=" + String(rev) +
               ", capture size=" + String(CAPTURE_SIZE), true, true);
      break;      
    }
  }
  //ether.staticSetup(myip); // actually not needed in this app
  ether.enableBroadcast();
  //ether.xx(); // promiscuous mode
}

void loop () {
  while (true) {
    word framelen = ether.packetReceive();
    if (framelen == 0)
      continue;
    recvd_frames++;
    switch_led();
    String s = dump_frame(ether.buffer, framelen);
    printstr(s, true, true);
  }
}

