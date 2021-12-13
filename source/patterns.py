ethernet_pattern = r'''###\[ Ethernet \]### 
  dst       = (.*)
  src       = (.*)
  type      = (.*)'''

ip_pattern = r'''###\[ IP \]### 
     version   = (.*)
     ihl       = (.*)
     tos       = (.*)
     len       = (.*)
     id        = (.*)
     flags     = (.*)
     frag      = (.*)
     ttl       = (.*)
     proto     = (.*)
     chksum    = (.*)
     src       = (.*)
     dst       = (.*)
     \\options   \\'''

tcp_pattern = r'''###\[ TCP \]### 
        sport     = (.*)
        dport     = (.*)
        seq       = (.*)
        ack       = (.*)
        dataofs   = (.*)
        reserved  = (.*)
        flags     = (.*)
        window    = (.*)
        chksum    = (.*)
        urgptr    = (.*)
        options   = (.*)'''

udp_pattern = r'''###\[ UDP \]### 
        sport     = (.*)
        dport     = (.*)
        len       = (.*)
        chksum    = (.*)'''

arp_pattern = r'''###\[ ARP \]### 
     hwtype    = (.*)
     ptype     = (.*)
     hwlen     = (.*)
     plen      = (.*)
     op        = (.*)
     hwsrc     = (.*)
     psrc      = (.*)
     hwdst     = (.*)
     pdst      = (.*)'''

icmp_pattern = r'''###\[ ICMP \]### 
        type      = (.*)
        code      = (.*)
        chksum    = (.*)
        id        = (.*)
        seq       = (.*)
        unused    = (.*)'''