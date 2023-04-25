import tkinter as tk
 
root = tk.Tk()
 
root.title("Packet Sniffer")
root.minsize(500,400)
label = tk.Label(root, text = "Welcome to the python networking tool", font=('Arial',18))
label.pack(padx=20,pady=20)
    
root.mainloop()