#using Scapy in a python script requires the .py file to be ran in root privilage
#run this .py file using: sudo python3 workspace.py

#Right now this is just a basic 10 line packet sniff to show functionality
import scapy.all  as scapy


def handler(packet):
    print(packet.summary())

def sniffing():
    scapy.sniff( prn=handler, store=9)

