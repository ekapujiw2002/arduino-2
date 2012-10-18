/*
 * Mini tcpdump for Arduino. Show information on received frames on Serial and LCD.
 *
 * v0.1
 */

#include <EtherCard.h>
#include "net.h"

#define HAVE_LCD
#ifdef HAVE_LCD
 #include <LiquidCrystal.h>
 LiquidCrystal lcd(8, 13, 9, 4, 5, 6, 7);
 #define LCD_COLS 16
 #define LCD_ROWS 2
#endif


// Ethernet interface MAC address
static byte mymac[] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa };
static byte myip[] = { 192,168,0,106 };

//BufferFiller bfill;

int led = HIGH;

char myipaddrstr[18] = { 0 };
char ipaddrstr[18] = { 0 };

void printstr(String s, int dbg_serial = 0 /* also serial debug with LCD */) {
#ifdef HAVE_LCD
  lcd.clear();
  //lcd.setCursor(0, 0);
  lcd.print(s.substring(0, LCD_COLS+1));
  if (s.length() > LCD_COLS) {
    lcd.setCursor(0, 1);
    lcd.print(s.substring(LCD_COLS, LCD_COLS*2));
   }
  if (dbg_serial)
    Serial.println(s);
#else
  Serial.println(s);
#endif
}

#define CAPTURE_SIZE (1500) //MAX_FRAMELEN
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
  ether.staticSetup(myip);
  ether.makeNetStr(myipaddrstr, myip, 4, '.', 10);
}

unsigned long int n = 0;

#define prh if (*p < 0xf) s += "0";s += String(*p, HEX);

void loop () {
  byte *p;
  word i;
  String s;
  word pktlen = ether.packetReceive();
  if (pktlen < ETH_HEADER_LEN)
     return;

  n++;
  // header
  s = String(n) + " " + String(pktlen) + " ";//pos="+String(pos);
  // src+dst MAC
  p = ether.buffer+ETH_SRC_MAC;
  for (i=0; i<6; i++) {
    if (*(p+i) < 0xf) s += "0";
    s += String(*(p+i), HEX);
  }
  p = ether.buffer+ETH_DST_MAC;
  s += ">";
  for (i=0; i<6; i++) {
    if (*(p+i) < 0xf) s += "0";
    s += String(*(p+i), HEX);
  }
  uint16_t ethproto = (*(ether.buffer+ETH_TYPE_H_P) << 8) + *(ether.buffer+ETH_TYPE_L_P);
  s += " " + String(ethproto, HEX);
  //p = ether.buffer+ETH_TYPE_H_P;  
  //prh;
  //p = ether.buffer+ETH_TYPE_L_P;  
  //prh;
  printstr(s, 1);

  word pos = ether.packetLoop(pktlen);
  if (pos) { // check if valid tcp data is received
    Serial.println("pkt");
    String s= millis()/1000 + ":";
    printstr(s, 1);
    digitalWrite(13, led);
    led = led == HIGH ? LOW : HIGH;
  }
}
