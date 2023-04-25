import tkinter as tk
 

class GUI:
    def __init__(self):

        self.root = tk.Tk()
        self.root.title("Packet Sniffer")
        self.root.minsize(500,400)
        self.label = tk.Label(self.root, text = "Welcome to the python networking tool", font=('Arial',18))
        self.label.pack(padx=20,pady=20)

        self.buttonframe = tk.Frame(self.root)
        self.buttonframe.columnconfigure(0,weight=1)
        self.buttonframe.columnconfigure(1,weight=1)
        # buttonframe.columnconfigure(2,weight=1)
        btn1 = tk.Button(self.buttonframe,text="Start Sniffing",font=('Arial',18),command = self.start_sniffing)
        btn2 = tk.Button(self.buttonframe,text = "End Sniffing",font=('Arial',18), command = self.stop_sniffing)
        btn1.grid(row=0, column =0, sticky=tk.W+tk.E)
        btn2.grid(row=0, column=1,sticky=tk.W+tk.E )
        self.buttonframe.pack(fill='x')

        self.root.mainloop()
    def start_sniffing(self):
        print("start sniffing")
        #functionality needs to be connected to function.py
    def stop_sniffing(self):
        print("stop sniffing")
        #functionality needs to be connected to function.py

GUI()