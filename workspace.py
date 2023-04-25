#using Scapy in a python script requires the .py file to be ran in root privilage
#run this .py file using: sudo python3 workspace.py
from scapy.all import *

a=sniff(count=10)
a.nsummary()
