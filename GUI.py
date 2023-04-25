import tkinter as tk
 
root = tk.Tk()
 
root.title("Packet Sniffer")
root.minsize(500,400)
label = tk.Label(root, text = "Welcome to the python networking tool", font=('Arial',18))
label.pack(padx=20,pady=20)




buttonframe = tk.Frame(root)
buttonframe.columnconfigure(0,weight=1)
buttonframe.columnconfigure(1,weight=1)
# buttonframe.columnconfigure(2,weight=1)
btn1 = tk.Button(buttonframe,text="Start Sniffing",font=('Arial',18))
btn2 = tk.Button(buttonframe,text = "End Sniffing",font=('Arial',18))
btn1.grid(row=0, column =0, sticky=tk.W+tk.E)
btn2.grid(row=0, column=1,sticky=tk.W+tk.E )
buttonframe.pack(fill='x')
root.mainloop()