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
source_ip_dict = collections.defaultdict(list)
count = Counter()


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
    global count
    treev
    # print(packet.show())
    print(packet.summary())

    if 'IP' in packet:
        src_ip = packet['IP'].src
        dest_ip = packet['IP'].dst

        if src_ip[0:len(subdomain)] == subdomain:
            if src_ip not in source_ip_dict:
                source_ip_dict[src_ip].append(dest_ip)

                row = treev.insert('', tk.END, text=src_ip,
                                   values=(src_ip, count.get(dest_ip)))
                treev.insert(row, tk.END, text=dest_ip, values=(dest_ip))
                treev.pack(fill=tk.X)
            else:
                if dest_ip not in source_ip_dict[src_ip]:
                    source_ip_dict[src_ip].append(dest_ip)
                    cur_item = treev.focus()
                    if (treev.item(cur_item)['text'] == src_ip):
                        treev.insert(cur_item, tk.END,
                                     text=dest_ip, values=(dest_ip))

            for ip in source_ip_dict:
                count[ip] += 1
    # this is where we find the specific row in the table and update the frequency
    # Find the item with the name 'Jane'
        item = None
        for child in treev.get_children():
            if treev.item(child)['values'][0] == 'Jane':
                item = child
                break

        if item is not None:
            treev.selection_set(item)
        treev.item(treev.selection(), values=(src_ip, count.get(dest_ip)))


def sniffing():
    scapy.sniff(prn=handler, stop_filter=stop_sniffing, count=100)
    print(count)


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

    plotly.offline.plot({"data": [plotly.graph_objs.Bar(x=xAxis, y=yAxis)]})

def stop_button():
    global should_stop
    global count
    should_stop = True


root = tk.Tk()
root.configure(bg="yellow")
root.title("Packet Sniffer")
root.minsize(800, 800)
label = tk.Label(
    root, text="Welcome to the python networking tool", font=('Arial', 18))
label.pack(padx=20, pady=20)

buttonframe = tk.Frame(root, bg="red")
buttonframe.columnconfigure(0, weight=1)
buttonframe.columnconfigure(1, weight=1)
# buttonframe.columnconfigure(2,weight=1)
btn1 = tk.Button(buttonframe, text="Start Sniffing",
                 font=('Arial', 18), fg='green',
                 activebackground='red', command=start_sniffing)
btn2 = tk.Button(buttonframe, text="End Sniffing",
                 font=('Arial', 18), fg='green',
                 activebackground='red', command=stop_button)

btn1.grid(row=0, column=0, sticky=tk.W+tk.E)
btn2.grid(row=0, column=1, sticky=tk.W+tk.E)
buttonframe.pack(fill='x')


# new textbox for count
textbox = tk.Text(root, height=25, width=25)
textbox.config(state='disabled')
textbox.pack()


subdomain_entry = tk.Entry(root)
subdomain_entry.pack(ipady=5, ipadx=50, pady=10)
treev = ttk.Treeview(root, height=400, column=(
    "IP", "Frequency"), show='headings')
treev.column('#0', minwidth=10, width=12)
treev.column("#1")
treev.column("#2")

treev.heading("#0", text="Type")

treev.heading("#1", text="address")
treev.heading("#2", text="frequency")


root.mainloop()
