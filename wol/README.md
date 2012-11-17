Sends Wake-on-LAN (WOL) magic packets to multiple destinations every 5 seconds.

Uses EtherCard library (for ENC28J60 Ethernet controller).

This is an alternative implementation for EtherCard::sendWol() which uses UDP
packets. This application creates Ethernet frames with protocol 0x0842 and as the
Ethernet payload appends directly the magic packet format:
six 0xff bytes + 16 times destination MAC.
