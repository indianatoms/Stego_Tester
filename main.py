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


def cmd_tcpip(ip_src, ip_dst, TOS, ttl, reserved, seq_num, window, urg_ptr, flags, payload, src_port):
    layer3 = IP()
    layer3.src = ip_src
    layer3.dst = ip_dst
    tos_num = int(TOS, 2)
    print(tos_num)
    layer3.tos = tos_num
    layer3.ttl = ttl
    layer3.ihl = 5

    layer4 = TCP()
    layer4.dport = 80
    layer4.sport = src_port
    num = int(reserved, 2)
    binary_num = bin(num)
    print(binary_num)
    layer4.reserved = num
    #    layer4.flags = "S"
    layer4.dataofs = 5
    layer4.flags = flags
    layer4.window = int(window, 2)
    layer4.urgptr = int(urg_ptr, 2)
    layer4.seq = int(seq_num, 2)

    print("1")
    if not(payload):
        pkt = layer3 / layer4
    else:
        pkt = layer3 / layer4 / payload
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
#IP
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

TOS_text = StringVar()
TOS_label = Label(app, text='TOS: ', font=('bold', 12), pady=10)
TOS_label.grid(row=4, column=2, sticky=W)
TOS_entry = Entry(app, textvariable=TOS_text)
TOS_entry.grid(row=4, column=3)

ttl_text = StringVar()
ttl_label = Label(app, text='ttl: ', font=('bold', 12), pady=10)
ttl_label.grid(row=5, column=2, sticky=W)
ttl_entry = Entry(app, textvariable=ttl_text)
ttl_entry.grid(row=5, column=3)

#TCP
reserved_bits_text = StringVar()
reserved_bits_label = Label(app, text='Reserved Bits: ', font=('bold', 12), pady=10)
reserved_bits_label.grid(row=6, column=0, sticky=W)
reserved_bits_entry = Entry(app, textvariable=reserved_bits_text)
reserved_bits_entry.grid(row=6, column=1)

window_text = StringVar()
window_label = Label(app, text='Window: ', font=('bold', 12), pady=10)
window_label.grid(row=7, column=0, sticky=W)
window_entry = Entry(app, textvariable=window_text)
window_entry.grid(row=7, column=1)

urgent_pointer_text = StringVar()
urgent_pointer_label = Label(app, text='Urgent Pointer: ', font=('bold', 12), pady=10)
urgent_pointer_label.grid(row=6, column=2, sticky=W)
urgent_pointer_entry = Entry(app, textvariable=urgent_pointer_text)
urgent_pointer_entry.grid(row=6, column=3)

seq_TCP_text = StringVar()
seq_TCP_label = Label(app, text='Seq Number: ', font=('bold', 12), pady=10)
seq_TCP_label.grid(row=7, column=2, sticky=W)
seq_TCP_entry = Entry(app, textvariable=seq_TCP_text)
seq_TCP_entry.grid(row=7, column=3)

flags_text = StringVar()
flags_label = Label(app, text='Flags: ', font=('bold', 12), pady=10)
flags_label.grid(row=6, column=4, sticky=W)
flags_entry = Entry(app, textvariable=flags_text)
flags_entry.grid(row=6, column=5)

payload_text = StringVar()
payload_label = Label(app, text='Payload: ', font=('bold', 12), pady=10)
payload_label.grid(row=7, column=4, sticky=W)
payload_entry = Entry(app, textvariable=payload_text)
payload_entry.grid(row=7, column=5)

sport_text = IntVar()
sport_label = Label(app, text='Source Port: ', font=('bold', 12), pady=10)
sport_label.grid(row=6, column=6, sticky=W)
sport_entry = Entry(app, textvariable=sport_text)
sport_entry.grid(row=6, column=7)


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
    print(seq_TCP_text.get())
    print(window_text.get())
    print(urgent_pointer_text.get())
    cmd_tcpip(src_TCP_text.get(), dst_TCP_text.get(), TOS_text.get(), ttl_text.get(), reserved_bits_text.get(), seq_TCP_text.get(), window_text.get(), urgent_pointer_text.get(), flags_text.get(),
              payload_text.get(), sport_text.get())


# buttons
icmp_steg_btn = Button(app, text='Send Ping', width=12, command=cmd, padx=10)
icmp_steg_btn.grid(row=3, column=0)

# buttons
icmp_steg_btn = Button(app, text='Send TCP/IP', width=12, command=cmd_TCP, padx=10)
icmp_steg_btn.grid(row=8, column=0)

app.title('Stego Tester')
app.geometry('1200x350')
app.mainloop()
# cmd_tcpip("192.168.1.104")
# cmd_ping("192.168.1.104", 4, 128, 1, 0)
