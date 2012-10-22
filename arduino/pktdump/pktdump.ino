/*
 * Mini tcpdump style application for Arduino and ENC28J60 Ethernet controller.
 * Uses the EtherCard library. This application shows information on received
 * Ethernet frames on Serial and/or LCD.
 *
 * v0.4
 */

// TODO:
// more length checks, more handlers for L3/L4 protocols, code commenting and cleanup,
// fix LCD code for other than 16x2 displays

#define prg_version "v0.4"

#include <EtherCard.h>
#include "defines.h"

// currently supports well 16x2 LCD screen
#define HAVE_LCD
#ifdef HAVE_LCD
 #include <LiquidCrystal.h>
 LiquidCrystal lcd(8, 13, 9, 4, 5, 6, 7);
 #define LCD_COLS 16
 #define LCD_ROWS 2
#endif

static byte mymac[] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
static byte myip[] = { 192,168,20,123 }; // not needed ?
//static byte myip[] = { 10,0,0,111}; // not needed ?

#define CAPTURE_SIZE (ETH_FRAME_LEN)
//#define CAPTURE_SIZE (14+20+1) // to test truncated frames
byte Ethernet::buffer[CAPTURE_SIZE];

void printstr(String s, int print_serial, int print_lcd = 0) {
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

// get Layer 2 (link) information
static const String l2_proto_str(byte *l2, unsigned int payload_len) {
  String s;
  int i;
  byte *p;
  uint16_t ethproto;

  s += "len=" + String(payload_len) + " ";
 
  // src+dst MAC
  p = ether.buffer + ETH_SRC_MAC;
  for (i = 0; i < 6; i++) {
    if (*(p + i) <= 0xf) s += '0';
    s += String(*(p + i), HEX);
    if (i != 5) s += ':';
  }
  p = ether.buffer + ETH_DST_MAC;
  s += '>';
  for (i = 0; i < 6; i++) {
    if (*(p + i) <= 0xf) s += '0';
    s += String(*(p + i), HEX);
    if (i != 5) s += ':';
  }

 s += ' ';
 
 ethproto = (*(l2 + ETH_TYPE_H_P) << 8) + *(l2 + ETH_TYPE_L_P);  
 for (i = 0; ether_protocol_str[i].str; i++) {
  if (ether_protocol_str[i].ether_proto == ethproto) {
    s += ether_protocol_str[i].str;
    break;
  }
 }
 
 if (!ether_protocol_str[i].str)
   s += "0x" + String(ethproto, HEX);

  return s;
}

// get Layer 3 (network) information
static const String l3_proto_str(byte *l3, unsigned int payload_len, uint16_t l3_proto,
                                 int *l3_len, uint16_t *l4_proto) {
  String s;
  *l3_len = 0;
  *l4_proto = 0; // todo: check if 0 is valid proto for the L3 protocol
  printstr("payload_len l3="+String(payload_len), 1);

  switch (l3_proto) {
    case ETHERTYPE_IP: {
//printstr("ETHERTYPE_IP", 1, 1);
      struct iphdr *ip = (struct iphdr *) l3;

//char str[200];
//sprintf(str, "<len=%u>",ip->tot_len); 
//s += str;
//printstr("sof="+String(sizeof(struct iphdr))+" ihl="+String(ip->ihl << 2), 1, 1);
      if ((payload_len < sizeof(struct iphdr)) || (payload_len < (ip->ihl << 2)) ) {
//printstr("trl3", 1, 1);
        *l3_len = -1;
        return s;
      }
      *l3_len = ip->ihl << 2;
      *l4_proto = ip->protocol;
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
      break;
    }
    default: {
//printstr("default", 1, 1);
      s += "protocol 0x" + String(l3_proto, HEX);
      s += " len=" + String(payload_len);
      *l3_len = payload_len; // for unknown L3 protocols so that L4 is not anymore done
      break;
    }
  }
  return s;
}

// get Layer 4 (transport) information
static const String l4_proto_str(byte *l4, unsigned int payload_len, uint16_t l4_proto) {
  String s;
  
  printstr("payload_len l4="+String(payload_len), 1);
  s += "len=" + String(payload_len);
  // TODO
  return s;
}

int led = HIGH;

void switch_led(void) {
  // switch LED state when a frame was received
  digitalWrite(LED_PIN, led);
  led = led == HIGH ? LOW : HIGH;
}

unsigned long int recvd_frames = 0;

String dump_frame(byte *frame, word framelen) {
  String s;
  String l2_str, l3_str, l4_str;
  uint16_t l3_proto = 0, l4_proto = 0;
  unsigned int payload_len = framelen;

  s = '#' + String(recvd_frames);

  if (framelen < ETH_HEADER_LEN) {
     s += String(" short frame");
     printstr(s, 1, 1);
     return s;
  }

  l2_str = l2_proto_str(ether.buffer, framelen);
  s += " L2:" + l2_str;

  printstr("payload_len l2="+String(payload_len), 1);

  l3_proto = (*(ether.buffer + ETH_TYPE_H_P) << 8) + *(ether.buffer + ETH_TYPE_L_P);  
  int l3_len = 0;
  
  payload_len -= ETH_HEADER_LEN; // remaining length in buffer now, L3+L4..
  
  l3_str = l3_proto_str(ether.buffer + ETH_HEADER_LEN, payload_len, l3_proto, &l3_len, &l4_proto);
  //if (l3_str.length() > 0) {
  if (l3_len >= 0) {
    s += "\n L3:" + l3_str;
    //s = l3_str;

    payload_len -= l3_len; // remaining length in buffer, L4..
    if (payload_len > 0) { // check L4 only if we knew how to handle L3 and there is L4 data left
      l4_str = l4_proto_str(ether.buffer + ETH_HEADER_LEN + l3_len, payload_len, l4_proto);
      if (l4_str.length() > 0) {
        s += "\n  L4:" + l4_str;
      } else {
        //s += " unknown L4";
      }
    }
  } else if (l3_len < 0) {
    s += " (truncated L3)";
  }
  return s;
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
      printstr("Failed to access Ethernet controller", 1, 1);
      delay(1000);
    } else {
      printstr("pktdump " prg_version ", controller revision=" + String(rev) +
               ", capture size=" + String(CAPTURE_SIZE), 1, 1);
      break;
    }
  }
  //ether.staticSetup(myip); // not needed ?
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
    printstr(s, 1, 1);
  }
}

