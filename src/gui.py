import tkinter
from tkinter import ttk


root = tkinter.Tk()
root.title("Network Sniffer  赵旭 2022E8015082079")
root.geometry('1200x700')


top_frame = tkinter.Frame(root)
top_frame.pack(side=tkinter.TOP, fill=tkinter.X)

start_button = tkinter.Button(top_frame, text="开始抓包")
start_button.pack(side=tkinter.LEFT, padx=5, pady=5)

stop_button = tkinter.Button(top_frame, text="停止抓包")
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