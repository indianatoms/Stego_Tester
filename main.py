from time import sleep
from tkinter import *

from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, sr1
import random


def cmd_ping(ip_dst, ip_src, seq, icmp_id):
    conf.verb = False

    layer3 = IP()
    layer3.src = ip_src
    layer3.dst = ip_dst
    layer3.tos = 0
    layer3.id = 1
    layer3.flags = 0
    layer3.frag = 0
    layer3.ttl = 128
    layer3.proto = 1  # icmp

    layer4 = ICMP()
    layer4.type = 8  # echo-request
    layer4.code = 0
    layer4.id = icmp_id
    layer4.seq = seq
    pkt = layer3 / layer4 / b"abcdefghijklmn opqrstuvwabcdefg hi"
    send(pkt)
    print("Ping Sent")


def cmd_tcpip(ip_src, ip_dst, reserved):
    layer3 = IP()
    layer3.src = ip_src
    layer3.dst = ip_dst
    layer3.ttl = 255
    layer3.ihl = 5

    layer4 = TCP()
    layer4.dport = 80
    layer4.sport = 20
    num = int(reserved, 2)
    binary_num = bin(num)
    print(binary_num)
    layer4.reserved = num
    #    layer4.flags = "S"
    layer4.dataofs = 5
    layer4.flags = 'SU'
    layer4.window = 0b011
    layer4.urgptr = 0b000111


    print("1")
    pkt = layer3 / layer4
    send(pkt)


# window object
app = Tk()

# ICMP texts listners
src_text = StringVar()
src_label = Label(app, text='Source IP: ', font=('bold', 12), pady=10)
src_label.grid(row=0, column=0, sticky=W)
src_entry = Entry(app, textvariable=src_text)
src_entry.grid(row=0, column=1)

dst_text = StringVar()
dst_label = Label(app, text='Destination IP: ', font=('bold', 12), pady=10)
dst_label.grid(row=1, column=0, sticky=W)
dst_entry = Entry(app, textvariable=dst_text)
dst_entry.grid(row=1, column=1)

id_text = IntVar()
id_label = Label(app, text='Ping ID: ', font=('bold', 12), pady=10)
id_label.grid(row=0, column=2, sticky=W)
id_entry = Entry(app, textvariable=id_text)
id_entry.grid(row=0, column=3)

seq_text = IntVar()
seq_label = Label(app, text='Ping Seq: ', font=('bold', 12), pady=10)
seq_label.grid(row=1, column=2, sticky=W)
seq_entry = Entry(app, textvariable=seq_text)
seq_entry.grid(row=1, column=3)

# TCP texts listners
src_TCP_text = StringVar()
src_label = Label(app, text='Source IP: ', font=('bold', 12), pady=10)
src_label.grid(row=4, column=0, sticky=W)
src_entry = Entry(app, textvariable=src_TCP_text)
src_entry.grid(row=4, column=1)

dst_TCP_text = StringVar()
dst_label = Label(app, text='Destination IP: ', font=('bold', 12), pady=10)
dst_label.grid(row=5, column=0, sticky=W)
dst_entry = Entry(app, textvariable=dst_TCP_text)
dst_entry.grid(row=5, column=1)

reserved_bits_text = StringVar()
reserved_bits_label = Label(app, text='Reserved Bits: ', font=('bold', 12), pady=10)
reserved_bits_label.grid(row=4, column=2, sticky=W)
reserved_bits_entry = Entry(app, textvariable=reserved_bits_text)
reserved_bits_entry.grid(row=4, column=3)

window_text = StringVar()
window_label = Label(app, text='Window: ', font=('bold', 12), pady=10)
window_label.grid(row=5, column=2, sticky=W)
window_entry = Entry(app, textvariable=window_text)
window_entry.grid(row=5, column=3)

urgent_pointer_text = StringVar()
urgent_pointer_label = Label(app, text='Urgent Pointer: ', font=('bold', 12), pady=10)
urgent_pointer_label.grid(row=4, column=4, sticky=W)
urgent_pointer_entry = Entry(app, textvariable=urgent_pointer_text)
urgent_pointer_entry.grid(row=4, column=5)

seq_TCP_text = StringVar()
seq_TCP_label = Label(app, text='Seq Number: ', font=('bold', 12), pady=10)
seq_TCP_label.grid(row=5, column=4, sticky=W)
seq_TCP_entry = Entry(app, textvariable=seq_TCP_text)
seq_TCP_entry.grid(row=5, column=5)


def cmd():
    print(dst_text.get())
    print(src_text.get())
    print(seq_text.get())
    print(id_text.get())
    cmd_ping(dst_text.get(), src_text.get(), seq_text.get(), id_text.get())


def cmd_TCP():
    print(dst_TCP_text.get())
    print(src_TCP_text.get())
    print(reserved_bits_text.get())
    print(window_text.get())
    print(urgent_pointer_text.get())
    cmd_tcpip(src_TCP_text.get(), dst_TCP_text.get(), reserved_bits_text.get())


# buttons
icmp_steg_btn = Button(app, text='Send Ping', width=12, command=cmd, padx=10)
icmp_steg_btn.grid(row=3, column=0)

# buttons
icmp_steg_btn = Button(app, text='Send TCP', width=12, command=cmd_TCP, padx=10)
icmp_steg_btn.grid(row=6, column=0)

app.title('Stego Tester')
app.geometry('800x250')
app.mainloop()
# cmd_tcpip("192.168.1.104")
# cmd_ping("192.168.1.104", 4, 128, 1, 0)
