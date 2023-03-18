import tkinter
from tkinter import ttk
from scapy.all import sniff

root = tkinter.Tk()
root.title("Network Sniffer  赵旭 2022E8015082079")
root.geometry('1200x700')
packet_counter = 0
current_packet = None

def start_sniffing():
    global current_packet
    start_button.configure(state="disabled")
    stop_button.configure(state="normal")
    current_packet = sniff(count=2 , store=False)
    print(current_packet)
  

def stop_sniffing():
    global current_packet
    stop_button.configure(state="disabled")
    start_button.configure(state="normal")
    current_packet = None
    


def process_packet(packet):
    global packet_counter, tree
    
    if current_packet is None:
        return

    packet_counter += 1
    row_data = [
        packet_counter,
        packet.time,
        packet.src,
        packet.dst,
        packet.proto,
        packet.len
    ]
    tree.insert("", tkinter.END, values=row_data)

top_frame = tkinter.Frame(root)
top_frame.pack(side=tkinter.TOP, fill=tkinter.X)

start_button = tkinter.Button(top_frame, text="开始抓包", command=start_sniffing)
start_button.pack(side=tkinter.LEFT, padx=5, pady=5)

stop_button = tkinter.Button(top_frame, text="停止抓包", command=stop_sniffing)
stop_button.pack(side=tkinter.LEFT, padx=5, pady=5)

clear_button = tkinter.Button(top_frame, text="清除")
clear_button.pack(side=tkinter.LEFT, padx=5, pady=5)


middle_frame =  tkinter.Frame(root)
middle_frame.pack(side= tkinter.TOP, fill= tkinter.BOTH, expand=True)

tree_columns = ("序号", "时间", "源IP", "目的IP", "协议", "长度")
tree = ttk.Treeview(middle_frame, columns=tree_columns, show="headings")
for col in tree_columns:
    tree.heading(col, text=col)
tree.pack(side= tkinter.TOP, fill= tkinter.BOTH, expand=True)

# tree.bind("<ButtonRelease-1>", show_packet_info)

bottom_frame =  tkinter.Frame(root)
bottom_frame.pack(side=tkinter.BOTTOM, fill=tkinter.X)

packet_text = tkinter.Text(bottom_frame, height=20)
packet_text.pack(side=tkinter.LEFT, padx=5, pady=5, fill=tkinter.X, expand=True)


root.mainloop()