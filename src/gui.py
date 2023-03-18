import tkinter
import time
from tkinter import ttk
from scapy.all import *
import asyncio

root = tkinter.Tk()
root.title("Network Sniffer")
root.geometry('1200x700')
packet_counter = 0
current_packet = None
stopFlag = False

def start_sniffing():
    global current_packet, stopFlag
    stopFlag = False
    start_button.configure(state="disabled")
    stop_button.configure(state="normal")
    current_packet = sniff(count=0, prn=process_packet)

  

def stop_sniffing():
    global current_packet, stopFlag
    stopFlag = True
    stop_button.configure(state="disabled")
    start_button.configure(state="normal")
    current_packet = None
    
    


def process_packet(packet):
    global packet_counter, tree
    
    if stopFlag:
        return
    packetstr = packet.show(dump=True)
    packet_counter += 1
    if packet.haslayer('IP'):
        row_data = [
            packet_counter,
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time)),
            packet['IP'].src,
            packet['IP'].dst,
            packet.proto,
            packet.len,
            packetstr
        ]
        tree.insert("", tkinter.END, values=row_data)
        tree.update()  # 更新tree
        root.update()
    # else:
    #     row_data = [
    #         packet_counter,
    #         time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time)),
    #         packet.src,
    #         packet.dst,
    #         packet.proto,
    #         packet.len
    #     ]

def show_packet_info(event):
    global tree, packet_text
    selected_item = tree.selection()[0]
    packet_text.delete("1.0", tkinter.END)
    packet_text.insert(tkinter.END, f"Packet {selected_item}\n")
    packet_text.insert(tkinter.END, f"{tree.item(selected_item)['values'][6]}")
    

top_frame = tkinter.Frame(root)
top_frame.pack(side=tkinter.TOP, fill=tkinter.X)

start_button = tkinter.Button(top_frame, text="开始抓包", command=start_sniffing)
start_button.pack(side=tkinter.LEFT, padx=5, pady=5)

stop_button = tkinter.Button(top_frame, text="停止抓包", command=stop_sniffing, state="disabled")
stop_button.pack(side=tkinter.LEFT, padx=5, pady=5)

clear_button = tkinter.Button(top_frame, text="清除")
clear_button.pack(side=tkinter.LEFT, padx=5, pady=5)


middle_frame =  tkinter.Frame(root)
middle_frame.pack(side= tkinter.TOP, fill= tkinter.BOTH, expand=True)

tree_columns = ("序号", "时间", "源地址", "目标地址", "协议", "长度")
tree = ttk.Treeview(middle_frame, columns=tree_columns, show="headings")
for col in tree_columns:
    tree.heading(col, text=col)
tree.pack(side= tkinter.TOP, fill= tkinter.BOTH, expand=True)

tree.bind("<ButtonRelease-1>", show_packet_info)

bottom_frame =  tkinter.Frame(root)
bottom_frame.pack(side=tkinter.BOTTOM, fill=tkinter.X)

packet_text = tkinter.Text(bottom_frame, height=20)
packet_text.pack(side=tkinter.LEFT, padx=5, pady=5, fill=tkinter.X, expand=True)


root.mainloop()