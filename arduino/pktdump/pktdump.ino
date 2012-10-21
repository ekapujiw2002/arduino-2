/*
 * Mini tcpdump for Arduino. Show information on received frames on Serial and/or LCD.
 *
 * v0.2
 */

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
//static byte myip[] = { 192,168,20,123 };

//BufferFiller bfill;

int led = HIGH;

//char myipaddrstr[18] = { 0 };
//char ipaddrstr[18] = { 0 };

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

#define CAPTURE_SIZE (ETH_FRAME_LEN)
byte Ethernet::buffer[CAPTURE_SIZE];

void setup () {
  Serial.begin(9600);
#ifdef HAVE_LCD
  lcd.begin(LCD_COLS, LCD_ROWS);
#endif
  pinMode(13, OUTPUT);
  uint8_t rev = ether.begin(CAPTURE_SIZE, mymac);
  if (rev == 0)
    Serial.println("Failed to access Ethernet controller");
  printstr("pktdump rev="+String(rev)+" bufsize="+String(CAPTURE_SIZE), 1);
//  ether.staticSetup(myip);
//  ether.makeNetStr(myipaddrstr, myip, 4, '.', 10);
}

unsigned long int n = 0;

#define prh if (*p < 0xf) s += "0";s += String(*p, HEX);

//static char t[10];

//static const char *l2_proto_str(uint16_t ether_proto) {
// get Layer 2 (link) information
static const String l2_proto_str(byte *l2) {
  String s;
  int i;// = 0;
  byte *p;
  uint16_t ethproto;

  // src+dst MAC
  p = ether.buffer + ETH_SRC_MAC;
  for (i = 0; i < 6; i++) {
    if (*(p + i) < 0xf) s += '0';
    s += String(*(p + i), HEX);
  }
  p = ether.buffer + ETH_DST_MAC;
  s += '>';
  for (i = 0; i < 6; i++) {
    if (*(p + i) < 0xf) s += '0';
    s += String(*(p + i), HEX);
  }

 s += ' ';
 
 ethproto = (*(l2 + ETH_TYPE_H_P) << 8) + *(l2 + ETH_TYPE_L_P);  
 for (i = 0; ether_protocol_str[i].str; i++) {
  if (ether_protocol_str[i].ether_proto == ethproto) {
    //return ether_protocol_str[i].str;
    s += ether_protocol_str[i].str;
    break;
  }
 }
 
 if (!ether_protocol_str[i].str)
   s += "0x" + String(ethproto, HEX);

  return s;
}

// get Layer 3 (network) information
static const String l3_proto_str(byte *l3) {
  return "L3";
}

// get Layer 4 (transport) information
static const String l4_proto_str(byte *l4) {
  //ether.makeNetStr(myipaddrstr, myip, 4, '.', 10);
  return "L4";
}

void loop () {
//  byte *p;
  //word i;
  String s;
  String l2_str, l3_str, l4_str;
  word framelen = ether.packetReceive();
  if (framelen == 0)
     return;

  // switch LED state when a frame was received
  digitalWrite(13, led);
  led = led == HIGH ? LOW : HIGH;

  if (framelen < ETH_HEADER_LEN) {
     printstr(String("Received frame too short, ") + String(framelen, DEC), 1, 1);
     return;
  }

  n++;
//  uint16_t ethproto = (*(ether.buffer+ETH_TYPE_H_P) << 8) + *(ether.buffer+ETH_TYPE_L_P);

  s = '#' + String(n) + " len=" + String(framelen);

  l2_str = l2_proto_str(ether.buffer);
  if (l2_str.length() > 0) {
    s += " L2:" + l2_str;
    l3_str = l3_proto_str(ether.buffer + ETH_HEADER_LEN);
    if (l3_str.length() > 0) {
      s += " L3:" + l3_str;
      int l3len = 0;
      l4_str = l4_proto_str(ether.buffer + ETH_HEADER_LEN + l3len);
      if (l4_str.length() > 0) {
        s += " L4:" + l4_str;
      } else {
        s += " !L4";
      }
    } else {
      s += " !L3";
    }
  } else {
    s += " !L2";  
  }
  
  printstr(s, 1, 1);
#if 0
  word pos = ether.packetLoop(framelen);
  if (pos) { // check if valid tcp data is received
    Serial.println("pkt");
    String s= millis()/1000 + ":";
    printstr(s, 1);
    digitalWrite(13, led);
    led = led == HIGH ? LOW : HIGH;
  }
  #endif
}
