import tkinter
import time
from tkinter import ttk
from scapy.all import sniff,hexdump
from scapy.arch.windows import get_windows_if_list
import threading
from scapy.layers.inet import IP,UDP,TCP,Ether
from ttkbootstrap import Style

#########初始化
root = tkinter.Tk()
root.title("嗅探器设计与实现 赵旭 2022E8015082079 ")
root.geometry('1200x700')
packet_counter = 0
packet_list = []
current_packet = None
stopFlag  = threading.Event()
iface_id =''
ifaces = get_windows_if_list()
iface_details = []
iface_name = []

types = {0x0800:'IPv4',0x0806:'ARP',0x86dd:'IPv6',0x88cc:'LLDP',0x891D:'TTE'}
protos_tcp = {20: 'ftp_data', 21: 'Ftp', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'Http', 443: 'Https'}
protos_ipv4 = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89:'OSPF'}

filter_list = []
filter_flag = False
filter_porto = ''
filter_add_flag = True
for iface in ifaces:
    iface_details.append((iface['description']))
    iface_name.append(iface['name'])

style = Style(theme='flatly')


#########回调函数
def start_sniffing():
    global  stopFlag
    stopFlag.clear()
    start_button.configure(state="disabled")
    stop_button.configure(state="normal")
    newt = threading.Thread(target=sniff_thread)
    newt.start()

def sniff_thread():
    global current_packet
    brf_str=brf_entry.get()
    print(brf_str)
    current_packet = sniff(count=0, 
                        prn=process_packet,
                        filter=brf_str,
                        iface=iface_id, 
                        stop_filter=(lambda x: stopFlag.is_set())
                        )


def stop_sniffing():
    global current_packet, stopFlag
    stopFlag.set()
    stop_button.configure(state="disabled")
    start_button.configure(state="normal")
    current_packet = None

def process_packet(packet):
    global packet_counter, tree, packet_list, filter_flag
    packet_flag = True
    if filter_flag:
        packet_flag = False

    packetstr = packet.show(dump=True)
    packet_counter += 1
    packet_list.append(packet)
    data_src = packet[Ether].src
    data_dst = packet[Ether].dst
    data_type = packet[Ether].type

    if data_type in types:
        proto = types[data_type]
    else:
        proto = 'LOOP'
    if proto == filter_porto: ##filter
        packet_flag = True

    if proto == 'IPv4':
        data_src = packet[IP].src
        data_dst = packet[IP].dst
        proto=packet[IP].proto
        if proto in protos_ipv4:
            proto=protos_ipv4[proto]
        if proto == filter_porto:##filter
            packet_flag = True

    if TCP in packet:     
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if sport in protos_tcp:
            proto = protos_tcp[sport]
        elif dport in protos_tcp:
            proto = protos_tcp[dport]
        if proto == filter_porto:##filter
            packet_flag = True

    elif UDP in packet:
        if packet[UDP].sport == 53 or packet[UDP].dport == 53:
            proto = 'DNS'
    
    bin_raw = hexdump(packet, dump=True)

    row_data = [
        packet_counter,
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time)),
        data_src,
        data_dst,
        proto,
        len(packet),
        packet.summary(),
        packetstr,
        bin_raw
    ]
    if packet_flag:
        tree.insert("", tkinter.END, values=row_data)
        tree.update()  
        tree.yview_moveto(1)
    # root.update()

def button_clear():
    global packet_counter
    tree.delete(*tree.get_children())
    packet_text.delete("1.0", tkinter.END)
    packet_counter = 0
    # packet_list=[]

def button_clearall():
    global packet_list
    button_clear()
    packet_list=[]

def show_packet_info(event):
    global tree, packet_text
    selected_item = tree.selection()[0]
    packet_text.delete("1.0", tkinter.END)
    packet_text.insert(tkinter.END, f"Packet {selected_item}\n")
    packet_text.insert(tkinter.END, f"{tree.item(selected_item)['values'][7]}")
    packet_text.insert(tkinter.END, f"二进制原文为：\n")
    packet_text.insert(tkinter.END, f"{tree.item(selected_item)['values'][8]}")
    

def on_select(event):
    global iface_id
    iface_des=combobox.get()
    iface_id=iface_name[iface_details.index(iface_des)]

def pro_select(event):
    global filter_flag, filter_list, packet_list, filter_porto
    filter_porto=pro_combobox.get()
    if filter_porto == 'Any':
        filter_flag = False
    else:
        filter_flag = True
    button_clear()
    filter_list = packet_list.copy()
    for packet in filter_list:
        process_packet(packet)
    packet_list = filter_list.copy()

#########GUI
# ttk.Style().theme_use('clam')
#########功能部分
top_frame = tkinter.Frame(root)
top_frame.pack(side=tkinter.TOP, fill=tkinter.X)

iface_label = ttk.Label(top_frame, text="网卡列表",style='primary.TLabel')
brf_label = ttk.Label(top_frame, text="BRF规则",style='primary.TLabel')
pro_label = ttk.Label(top_frame, text="协议过滤",style='primary.TLabel')

combobox = ttk.Combobox(top_frame, values=iface_details,width=30)
combobox.bind("<<ComboboxSelected>>", on_select)
combobox.current(0)
on_select(None)

proList = ['Any', 'IPv4', 'IPv6', 'ftp_data', 'Ftp', 'SSH', 'Telnet', 'SMTP', 'Http', 
           'Https', 'ICMP', 'IGMP', 'IP', 'TCP', 'EGP', 'IGP', 'UDP', 'ESP', 'OSPF']

pro_combobox = ttk.Combobox(top_frame, values=proList,width=10)
pro_combobox.bind("<<ComboboxSelected>>", pro_select)
pro_combobox.current(0)


start_button = tkinter.Button(top_frame, text="开始抓包", command=start_sniffing)

stop_button = tkinter.Button(top_frame, text="停止抓包", command=stop_sniffing, state="disabled")

clear_button = tkinter.Button(top_frame, text="清除列表",command=button_clear)

clearall_button = tkinter.Button(top_frame, text="清除缓存",command=button_clearall)

brf_entry = tkinter.Entry(top_frame, width=50)

brf_label.pack(side=tkinter.LEFT, padx=5, pady=0)
brf_entry.pack(side=tkinter.LEFT, padx=0, pady=5)
start_button.pack(side=tkinter.LEFT, padx=5, pady=5)
stop_button.pack(side=tkinter.LEFT, padx=5, pady=5)
clear_button.pack(side=tkinter.LEFT, padx=5, pady=5)
clearall_button.pack(side=tkinter.LEFT, padx=5, pady=5)
iface_label.pack(side=tkinter.LEFT, padx=5, pady=0)
combobox.pack(side=tkinter.LEFT, padx=0, pady=5)
pro_label.pack(side=tkinter.LEFT, padx=5, pady=0)
pro_combobox.pack(side=tkinter.LEFT, padx=0, pady=5)
#########数据包网格

middle_frame =  tkinter.Frame(root)
middle_frame.pack(side= tkinter.TOP, fill= tkinter.BOTH, expand=True)

tree_columns = ("序号", "时间", "源地址", "目标地址", "协议", "长度", "简要信息")

tree = ttk.Treeview(middle_frame, columns=tree_columns, show="headings")

widths =[30,80,80,80,30,30,350]

for col in tree_columns:
    tree.heading(col, text=col)
for i in range(len(tree_columns)):
    tree.column(tree_columns[i], width=widths[i])

tree_scrollbar = tkinter.Scrollbar(middle_frame, orient="vertical", command=tree.yview)
tree_scrollbar.pack(side="right", fill="y")

tree_h_scrollbar = tkinter.Scrollbar(middle_frame, orient="horizontal", command=tree.xview)
tree_h_scrollbar.pack(side="bottom", fill="x")

tree.configure(yscrollcommand=tree_scrollbar.set, xscrollcommand=tree_h_scrollbar.set)

tree.pack(side= tkinter.TOP, fill= tkinter.BOTH, expand=True)

tree.bind("<ButtonRelease-1>", show_packet_info)


#########数据包详情

bottom_frame = tkinter.Frame(root)
bottom_frame.pack(side=tkinter.BOTTOM, fill=tkinter.X)

packet_text = tkinter.Text(bottom_frame, height=15)
packet_text.pack(side=tkinter.LEFT, padx=5, pady=5, fill=tkinter.BOTH, expand=True)

yscrollbar = tkinter.Scrollbar(bottom_frame, command=packet_text.yview)
yscrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
packet_text.configure(yscrollcommand=yscrollbar.set)


root.mainloop()