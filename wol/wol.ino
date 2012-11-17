/*
 * Sends Wake-on-LAN (WOL) magic packets to multiple destinations every 5 seconds.
 *
 * Uses EtherCard library (for ENC28J60 Ethernet controller).
 *
 * This is an alternative implementation for EtherCard::sendWol() which uses UDP
 * packets. This application creates Ethernet frames with protocol 0x0842 and as the
 * Ethernet payload appends directly the magic packet format:
 * six 0xff bytes + 16 times destination MAC.
 *
 * Edit dstmacs array to contain the Ethernet MACs of the targets.
 */

#define prg_version "v1.0"

#include <EtherCard.h>

#define LED_PIN 13

// Ethernet/util.h
#define htons(x) ( ((x)<<8) | (((x)>>8)&0xFF) )

// net/ethernet.h
#define ETH_ALEN 6
struct ether_header {
  uint8_t  ether_dhost[ETH_ALEN]; 
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

// currently supports well 16x2 LCD screen
#define HAVE_LCD
#ifdef HAVE_LCD
 #include <LiquidCrystal.h>
 LiquidCrystal lcd(8, 13, 9, 4, 5, 6, 7); // this works for me, change for your case
 #define LCD_COLS 16
 #define LCD_ROWS 2
#endif

static byte mymac[] = { 'a', 'r', 'd', 'u', 'i', 'n' };
static byte dstmacs[][ETH_ALEN] = {
 { 0x00, 0x1c, 0x7e, 0x28, 0x35, 0xb6 },
 { 0xc8, 0x0a, 0xa9, 0xdb, 0x7d, 0x19 }
};

#define FRAME_SIZE (sizeof(struct ether_header) + 6 + 16*ETH_ALEN)
byte Ethernet::buffer[FRAME_SIZE];

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

void send_wol(byte *dstmac) {
  struct ether_header *eth = (struct ether_header *) Ethernet::buffer;
  byte *p;
  
  memcpy(eth->ether_shost, mymac, ETH_ALEN);
  memset(eth->ether_dhost, 0xff, ETH_ALEN);
  eth->ether_type = htons(0x0842);
  p = (byte *)(eth + 1);
  memset(p, 0xff, ETH_ALEN);
  p += ETH_ALEN;
  for (int i = 0; i < 16; i++, p += ETH_ALEN) {
   memcpy(p, dstmac, ETH_ALEN);
  }
  printstr(String(millis()/1000) + " WOL " + hexdump(dstmac, ETH_ALEN), true, true);
  EtherCard::packetSend(FRAME_SIZE);
  //or EtherCard::sendWol(dstmac);
}

void setup () {
  Serial.begin(9600);
#ifdef HAVE_LCD
  lcd.begin(LCD_COLS, LCD_ROWS);
#endif
  pinMode(LED_PIN, OUTPUT);
  while (true) {
    uint8_t rev = ether.begin(FRAME_SIZE, mymac);
    if (rev == 0) {
      printstr("Failed to access Ethernet controller", true, true);
      delay(1000);
    } else {
      printstr("wol " prg_version ", controller revision=" + String(rev), true, true);
      delay(3000);
      break;
    }
  }
}

void loop () {
  while (true) {
    for (unsigned int mac = 0; mac < sizeof(dstmacs) / ETH_ALEN; mac++) {
      digitalWrite(LED_PIN, HIGH);
      send_wol(dstmacs[mac]);
      digitalWrite(LED_PIN, LOW);
      delay(1000);
    }
    delay(5000);
  }
}

