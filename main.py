from time import sleep
from tkinter import *

from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, sr1
import random


def cmd_ping(ip_dst, ip_src, seq, id, verbose, timeout):
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
    layer4.id = id
    layer4.seq = seq

    pkt = layer3 / layer4 / b"abcdefghijklmn opqrstuvwabcdefg hi"
    ans = sr1(pkt, timeout=timeout)
    if ans:
        if verbose:
            ans.show()
        else:
            print(ans.summary())
            del ans
    else:
        print('Timeout')


def cmd_tcpip(ip):
    layer3 = IP()
    layer3.src = "192.168.1.107"
    layer3.dst = ip
    layer3.ttl = 255
    layer3.ihl = 5

    layer4 = TCP()
    layer4.dport = 80
    layer4.sport = 20
    layer4.reserved = 0b0111
    #    layer4.flags = "S"
    layer4.dataofs = 5
    layer4.flags = 'S'

    print("1")
    pkt = layer3 / layer4
    send(pkt)


# window object
app = Tk()

# texts listners
src_text = StringVar()
src_label = Label(app, text='Source IP: ', font=('bold', 12), pady=20)
src_label.grid(row=0, column=0, sticky=W)
src_entry = Entry(app, textvariable=src_text)
src_entry.grid(row=0, column=1)

dst_text = StringVar()
dst_label = Label(app, text='Destination IP: ', font=('bold', 12), pady=20)
dst_label.grid(row=1, column=0, sticky=W)
dst_entry = Entry(app, textvariable=dst_text)
dst_entry.grid(row=1, column=1)


def cmd():
    print("click")


# buttons
icmp_steg_btn = Button(app, text='Send Ping', width=12, command=cmd)
icmp_steg_btn.grid(row=3, column=0)

app.title('Stego Tester')
app.geometry('700x250')
app.mainloop()
# cmd_tcpip("192.168.1.104")
# cmd_ping("192.168.1.104", 4, 128, 1, 0)
