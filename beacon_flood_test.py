from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump
import sys

def ssid_list(ssid):
    ssid_name= []
    with open (ssid,'r') as f:
        lines = f.readlines()
        for line in lines:
            ssid_name.append(line.rstrip())
    return ssid_name


def beacon_frame(wlen,ssid):
    
    ssid_name = ssid_list(ssid)
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2='62:d3:37:31:cc:74', addr3='62:d3:37:31:cc:74')
    beacon = Dot11Beacon(cap='ESS')

    for _ in ssid_name :
        essid = Dot11Elt(ID='SSID',info=ssid_name, len=None)
        frame = RadioTap()/dot11/beacon/essid     
        frame.show()
        print("\nHexdump of frame:")
        hexdump(frame)
            
    sendp(frame, iface=wlen, inter=0.100, loop=1000)

if __name__ == '__main__':
    wlen_name = sys.argv[1]
    ssid_name = sys.argv[2]
    beacon_frame(wlen_name,ssid_name)

