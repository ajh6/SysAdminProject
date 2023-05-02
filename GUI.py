# using Scapy in a python script requires the .py file to be ran in root privilage
# run this .py file using: sudo python3 filename

import tkinter as tk
import sys
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import collections
import scapy.all as scapy
from collections import Counter
import plotly

from collections import Counter

thread = None
should_stop = False
subdomain = ''
source_ip_dict = collections.defaultdict(int)
count = Counter()


def start_sniffing():
    global should_stop
    global thread
    global subdomain

    subdomain = subdomain_entry.get()

    if (thread is None) or (not thread.is_alive()):
        should_stop = False
        thread = threading.Thread(target=sniffing).start()


def updateTable():
    global treev
    global source_ip_dict

    for item in treev.get_children():
        treev.delete(item)

    for ip in source_ip_dict:
        print(ip)
        treev.insert('', index=tk.END, text=ip, values=(ip, source_ip_dict[ip]))


def handler(packet):
    global source_ip_dict
    global subdomain
    global treev
    global count

    print(packet.summary())

    if 'IP' in packet:
        src_ip = packet['IP'].src
        #dest_ip = packet['IP'].dst
        count[src_ip] += 1
    
        if src_ip[0:len(subdomain)] == subdomain:

            if src_ip not in source_ip_dict:
                init = 1
                source_ip_dict[src_ip] = init
                updateTable()
                treev.pack(fill=tk.X)
        
            else:
                source_ip_dict[src_ip] += 1
                updateTable()
            

def sniffing():
    scapy.sniff(prn=handler, stop_filter=stop_sniffing)


def stop_sniffing(packet):
    global should_stop
    return should_stop


def stop_button():
    global should_stop
    should_stop = True

    xAxis = []
    yAxis = []

    for ip in count:
        xAxis.append(ip)
        yAxis.append(count[ip])

    print("Displaying Graph...")

    plotly.offline.plot({"data": [plotly.graph_objs.Bar(x=xAxis, y=yAxis)]})


root = tk.Tk()
root.configure(bg="yellow")
root.title("Packet Sniffer")
root.minsize(800, 800)

label = tk.Label(root, text="Welcome to the Python Networking Tool", font=('Arial', 18))
label.pack(padx=20, pady=20)

buttonframe = tk.Frame(root)
buttonframe.columnconfigure(0, weight=1)
buttonframe.columnconfigure(1, weight=1)
buttonframe.pack(fill='x')

btn1 = tk.Button(buttonframe, text="Start Sniffing", font=('Arial', 18), bg='green', fg='black', activebackground='red', command=start_sniffing)
btn2 = tk.Button(buttonframe, text="End Sniffing", font=('Arial', 18), bg='red', fg='black', activebackground='red', command=stop_button)
btn1.grid(row=0, column=0, sticky=tk.W+tk.E)
btn2.grid(row=0, column=1, sticky=tk.W+tk.E)


subdomain_entry = tk.Entry(root)

treev = ttk.Treeview(root, height=400, column=("IP", "Frequency"), show='headings')

treev.heading('#1', text='Source IP Address')
treev.heading('#2', text='Request Frequency')

root.mainloop()
