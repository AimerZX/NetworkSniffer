from scapy.all import *
import tkinter

package=sniff(iface= 'WLAN',count= 1)
# print(package[0].show())
root = tkinter.Tk()
testMsg = tkinter.Message(root, text=str(package[0].show()))
testMsg.pack()
root.mainloop()