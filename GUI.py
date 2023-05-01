import tkinter as tk
import sys
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import collections
import scapy.all as scapy

thread = None
should_stop = False
subdomain = ''
source_ip_dict = collections.defaultdict(list)


def start_sniffing():
        print("start sniffing")
        global should_stop
        global thread
        global subdomain

        subdomain = subdomain_entry.get()

        if (thread is None) or (not thread.is_alive()):
            should_stop = False
            thread = threading.Thread(target=sniffing).start()



def handler(packet):
        global source_ip_dict
        global subdomain
        treev
        print(packet.show())
        

        if 'IP' in packet:
            src_ip = packet['IP'].src
            dest_ip = packet['IP'].dst

            if src_ip[0:len(subdomain)] == subdomain:
                if src_ip not in source_ip_dict:
                    source_ip_dict[src_ip].append(dest_ip)

                    row = treev.insert('', index=tk.END, text=src_ip)
                    treev.insert(row, tk.END, text=dest_ip)
                    treev.pack(fill=tk.X)
            else:
                if dest_ip not in source_ip_dict[src_ip]:
                    source_ip_dict[src_ip].append(dest_ip)
                    cur_item = treev.focus()
                    if (treev.item(cur_item)['text'] == src_ip):
                        treev.insert(cur_item, tk.END, text=dest_ip)

def sniffing():
        scapy.sniff(prn=handler, stop_filter=stop_sniffing)

def stop_sniffing(packet):
        global should_stop
        return should_stop
def stop_button():
     global should_stop
     should_stop = True




root = tk.Tk()
root.title("Packet Sniffer")
root.minsize(800, 800)
label = tk.Label(
    root, text="Welcome to the python networking tool", font=('Arial', 18))
label.pack(padx=20, pady=20)

buttonframe = tk.Frame(root)
buttonframe.columnconfigure(0, weight=1)
buttonframe.columnconfigure(1, weight=1)
# buttonframe.columnconfigure(2,weight=1)
btn1 = tk.Button(buttonframe, text="Start Sniffing",
                      font=('Arial', 18), command=start_sniffing)
btn2 = tk.Button(buttonframe, text="End Sniffing",
                       font=('Arial', 18), command=stop_sniffing)
btn1.grid(row=0, column=0, sticky=tk.W+tk.E)
btn2.grid(row=0, column=1, sticky=tk.W+tk.E)
buttonframe.pack(fill='x')

subdomain_entry = tk.Entry(root)
subdomain_entry.pack(ipady=5, ipadx=50, pady=10)
treev = ttk.Treeview(root, height=400)
treev.column('#0')

root.mainloop()

