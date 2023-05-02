from tkinter import *
from tkinter import ttk
import collections


window = Tk()
window.geometry("500x500")
window.title('MAIN TITLE')

data = [
   ['1.1.1.1', 72],
   ['2.2.2.2', 43]
]

# addr = ['1.1.1.1', '2.2.2.2', '3.3.3.3']
# freq = [72, 43, 18]

table = ttk.Treeview(window, columns=('addresses', 'freq'), show='headings')

table.heading('addresses', text='IP Addresses')
table.heading('freq', text='Frequency')

table.pack()

count = 0
for ip in data:
   table.insert(parent='', index='end', iid=count, values=(ip[0], ip[1]))
   count += 1
#  iid=0, text="Parent",


window.mainloop()
