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

#define prg_version "v0.7"

#include <EtherCard.h>
#include "defines.h"

#define PRINT_IP
#define PRINT_ARP
//#define PRINT_VLAN
//#define PRINT_IPV6

#ifdef PRINT_IP
#include "print_ip.h"
#endif
#ifdef PRINT_ARP
#include "print_arp.h"
#endif
#ifdef PRINT_VLAN
#include "print_vlan.h"
#endif
#ifdef PRINT_IPV6
#include "print_ipv6.h"
#endif

static struct {
  uint16_t ether_proto;
  l3_printer printer;
} ether_protocol_handlers[] = {
#ifdef PRINT_IP
 { ETHERTYPE_IP, ip_print },
#endif
#ifdef PRINT_ARP
 { ETHERTYPE_ARP, arp_print },
#endif
#ifdef PRINT_VLAN
 { ETHERTYPE_VLAN, NULL },
#endif
#ifdef PRINT_IPV6
 { ETHERTYPE_IPV6, NULL },
#endif
 { 0, NULL }
};

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

String hexdump(byte *p, unsigned int len) {
  String s;
  for (unsigned int i = 0; i < len; i++, p++) {
    if (*p <= 0xf) s += '0';
    s += String(*p, HEX);
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
  ether.xx(); // promiscuous mode
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
