import tkinter
import time
from tkinter import ttk
from scapy.all import sniff
import threading
from scapy.layers.inet import *
from scapy.layers.l2 import *

root = tkinter.Tk()
root.title("Network Sniffer")
root.geometry('1200x700')
packet_counter = 0
packet_list = []
current_packet = None
stopFlag  = threading.Event()

def start_sniffing():
    global current_packet, stopFlag
    stopFlag.clear()
    start_button.configure(state="disabled")
    stop_button.configure(state="normal")
    current_packet = sniff(count=0, prn=process_packet, stop_filter=(lambda x: stopFlag.is_set()))


def stop_sniffing():
    global current_packet, stopFlag
    stopFlag.set()
    stop_button.configure(state="disabled")
    start_button.configure(state="normal")
    current_packet = None


def process_packet(packet):
    global packet_counter, tree
    
    packetstr = packet.show(dump=True)
    packet_counter += 1

    data_src = packet[Ether].src
    data_dst = packet[Ether].dst
    data_type = packet[Ether].type
    types = {0x0800:'IPv4',0x0806:'ARP',0x86dd:'IPv6',0x88cc:'LLDP',0x891D:'TTE'}
    if data_type in types:
        proto = types[data_type]
    else:
        proto = 'LOOP'
    if proto == 'IPv4':
        protos_ipv4 = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89:'OSPF'}
        data_src = packet[IP].src
        data_dst = packet[IP].dst
        proto=packet[IP].proto
        if proto in protos_ipv4:
            proto=protos_ipv4[proto]

    if TCP in packet:
        protos_tcp = {20: 'ftp_data', 21: 'Ftp', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'Http', 443: 'Https'}
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if sport in protos_tcp:
            proto = protos_tcp[sport]
        elif dport in protos_tcp:
            proto = protos_tcp[dport]
    elif UDP in packet:
        if packet[UDP].sport == 53 or packet[UDP].dport == 53:
            proto = 'DNS'
    
    row_data = [
        packet_counter,
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time)),
        data_src,
        data_dst,
        proto,
        len(packet),
        packet.summary(),
        packetstr
    ]
    tree.insert("", tkinter.END, values=row_data)
    tree.update()  
    # root.update()


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

tree_columns = ("序号", "时间", "源地址", "目标地址", "协议", "长度", "简要信息")
tree = ttk.Treeview(middle_frame, columns=tree_columns, show="headings")
for col in tree_columns:
    tree.heading(col, text=col)

tree_scrollbar = tkinter.Scrollbar(middle_frame, orient="vertical", command=tree.yview)
tree_scrollbar.pack(side="right", fill="y")

tree_h_scrollbar = tkinter.Scrollbar(middle_frame, orient="horizontal", command=tree.xview)
tree_h_scrollbar.pack(side="bottom", fill="x")

tree.configure(yscrollcommand=tree_scrollbar.set, xscrollcommand=tree_h_scrollbar.set)

tree.pack(side= tkinter.TOP, fill= tkinter.BOTH, expand=True)

tree.bind("<ButtonRelease-1>", show_packet_info)

bottom_frame = tkinter.Frame(root)
bottom_frame.pack(side=tkinter.BOTTOM, fill=tkinter.X)

packet_text = tkinter.Text(bottom_frame, height=20)
packet_text.pack(side=tkinter.LEFT, padx=5, pady=5, fill=tkinter.BOTH, expand=True)

yscrollbar = tkinter.Scrollbar(bottom_frame, command=packet_text.yview)
yscrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
packet_text.configure(yscrollcommand=yscrollbar.set)


root.mainloop()