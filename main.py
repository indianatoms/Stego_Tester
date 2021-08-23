from telnetlib import IP
import paho.mqtt.client as mqtt
from time import sleep
from tkinter import *
from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP


# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected OK")
    else:
        print("Bad connenction ", rc)

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.


def on_log(client, userdata, level, buf):
    print("log: " + buf)


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))

def sip_message(ip_dst, ip_src, CallID, mf, contact):
    sourcePort = 3001
    destinationIp = ip_dst
    sourceIp = ip_src
    ip = IP(src=sourceIp, dst=destinationIp)
    myPayload = (
        'INVITE sip:{0}:5060;transport=tcp SIP/2.0\r\n'
        'Via: SIP/2.0/UDP 192.168.44.32:5060;branch=1234\r\n'
        'From: \"somedevice\"<sip:somedevice@1.1.1.1:5060>;tag=5678\r\n'
        'To: <sip:{0}:5060>\r\n'
        'Call-ID: '+ CallID +' \r\n'
        'CSeq: 1 INVITE\r\n'
        'Max-Forwards: '+ mf +'\r\n'
        'Contact: <sip:'+ contact +'@pc33.atlanta.com>\r\n'
        'Content-Length: 0\r\n\r\n').format(destinationIp)
    udp = UDP(dport=5060, sport=sourcePort)
    send(ip / udp / myPayload)


def mqtt_message(broker, id, user, psw, topic, payload, keepalive, retainval):
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client = mqtt.Client(id)
    client.username_pw_set(user, password=psw)
    print("connecting to broker ", broker)
    sleep(10)
    client.connect(broker, 1883, keepalive)
    client.loop_start()
    client.publish(topic, payload, retain=retainval)
    client.loop_stop()
    client.disconnect()


def mqtt_subscribe(ip, id, user, psw, topic, clean):
    print(topic)
    client = mqtt.Client(client_id=id, clean_session=clean)
    client.on_connect = on_connect
    client.on_message = on_message
    broker = ip
    client.username_pw_set(user, password=psw)
    print("connecting to broker ", broker)
    client.loop_start()
    client.connect(broker)
    client.subscribe(topic)
    client.loop_forever()


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


def cmd_tcpip(ip_src, ip_dst, TOS, ttl, id, reserved, seq_num, window, urg_ptr, flags, payload, src_port):
    layer3 = IP()
    layer3.src = ip_src
    layer3.dst = ip_dst
    tos_num = int(TOS, 2)
    print(tos_num)
    layer3.tos = tos_num
    layer3.ttl = ttl
    layer3.ihl = 5
    layer3.id = id

    layer4 = TCP()
    layer4.dport = 80
    layer4.sport = src_port
    num = int(reserved, 2)
    binary_num = bin(num)
    print(binary_num)
    layer4.reserved = num
    #    layer4.flags = "S"
    layer4.flags = flags
    layer4.window = window
    layer4.urgptr = int(urg_ptr, 2)
    layer4.seq = seq_num

    print("1")
    if not payload:
        pkt = layer3 / layer4
    else:
        pkt = layer3 / layer4 / payload
    send(pkt)


# window object
app = Tk()
#style = Style()


# ICMP texts listners
icmp_label = Label(app, text='ICMP Packet: ', font=('bold', 14), pady=10)
icmp_label.grid(row=0, column=0, sticky=W)
src_text = StringVar()
src_label = Label(app, text='Source IP: ', font=('bold', 12), pady=10)
src_label.grid(row=1, column=0, sticky=W)
src_entry = Entry(app, textvariable=src_text)
src_entry.grid(row=1, column=1)

dst_text = StringVar()
dst_label = Label(app, text='Destination IP: ', font=('bold', 12), pady=10)
dst_label.grid(row=2, column=0, sticky=W)
dst_entry = Entry(app, textvariable=dst_text)
dst_entry.grid(row=2, column=1)

id_text = IntVar()
id_label = Label(app, text='Ping ID: ', font=('bold', 12), pady=10)
id_label.grid(row=1, column=2, sticky=W)
id_entry = Entry(app, textvariable=id_text)
id_entry.grid(row=1, column=3)

seq_text = IntVar()
seq_label = Label(app, text='Ping Seq: ', font=('bold', 12), pady=10)
seq_label.grid(row=2, column=2, sticky=W)
seq_entry = Entry(app, textvariable=seq_text)
seq_entry.grid(row=2, column=3)

# TCP texts listners
# IP
tcp_label = Label(app, text='TCP Packet: ', font=('bold', 14), pady=10)
tcp_label.grid(row=4, column=0, sticky=W)

src_TCP_text = StringVar()
src_label = Label(app, text='Source IP: ', font=('bold', 12), pady=10)
src_label.grid(row=5, column=0, sticky=W)
src_entry = Entry(app, textvariable=src_TCP_text)
src_entry.grid(row=5, column=1)

dst_TCP_text = StringVar()
dst_label = Label(app, text='Destination IP: ', font=('bold', 12), pady=10)
dst_label.grid(row=6, column=0, sticky=W)
dst_entry = Entry(app, textvariable=dst_TCP_text)
dst_entry.grid(row=6, column=1)

TOS_text = StringVar()
TOS_label = Label(app, text='TOS: ', font=('bold', 12), pady=10)
TOS_label.grid(row=5, column=2, sticky=W)
TOS_entry = Entry(app, textvariable=TOS_text)
TOS_entry.grid(row=5, column=3)

ttl_text = IntVar()
ttl_label = Label(app, text='ttl: ', font=('bold', 12), pady=10)
ttl_label.grid(row=6, column=2, sticky=W)
ttl_entry = Entry(app, textvariable=ttl_text)
ttl_entry.grid(row=6, column=3)

ip_id_text = IntVar()
ip_id_label = Label(app, text='IP ID: ', font=('bold', 12), pady=10)
ip_id_label.grid(row=6, column=4, sticky=W)
ip_id_entry = Entry(app, textvariable=ip_id_text)
ip_id_entry.grid(row=6, column=5)

# TCP
reserved_bits_text = StringVar()
reserved_bits_label = Label(app, text='Reserved Bits: ', font=('bold', 12), pady=10)
reserved_bits_label.grid(row=7, column=0, sticky=W)
reserved_bits_entry = Entry(app, textvariable=reserved_bits_text)
reserved_bits_entry.grid(row=7, column=1)

window_text = IntVar()
window_label = Label(app, text='Window: ', font=('bold', 12), pady=10)
window_label.grid(row=8, column=0, sticky=W)
window_entry = Entry(app, textvariable=window_text)
window_entry.grid(row=8, column=1)

urgent_pointer_text = StringVar()
urgent_pointer_label = Label(app, text='Urgent Pointer: ', font=('bold', 12), pady=10)
urgent_pointer_label.grid(row=7, column=2, sticky=W)
urgent_pointer_entry = Entry(app, textvariable=urgent_pointer_text)
urgent_pointer_entry.grid(row=7, column=3)

seq_TCP_text = IntVar()
seq_TCP_label = Label(app, text='Seq Number: ', font=('bold', 12), pady=10)
seq_TCP_label.grid(row=8, column=2, sticky=W)
seq_TCP_entry = Entry(app, textvariable=seq_TCP_text)
seq_TCP_entry.grid(row=8, column=3)

flags_text = StringVar()
flags_label = Label(app, text='Flags: ', font=('bold', 12), pady=10)
flags_label.grid(row=7, column=4, sticky=W)
flags_entry = Entry(app, textvariable=flags_text)
flags_entry.grid(row=7, column=5)

payload_text = StringVar()
payload_label = Label(app, text='Payload: ', font=('bold', 12), pady=10)
payload_label.grid(row=8, column=4, sticky=W)
payload_entry = Entry(app, textvariable=payload_text)
payload_entry.grid(row=8, column=5)

sport_text = IntVar()
sport_label = Label(app, text='Source Port: ', font=('bold', 12), pady=10)
sport_label.grid(row=7, column=6, sticky=W)
sport_entry = Entry(app, textvariable=sport_text)
sport_entry.grid(row=7, column=7)


##MQTT Broker
mqtt_label = Label(app, text='MQTT Packet: ', font=('bold', 14), pady=10)
mqtt_label.grid(row=10, column=0, sticky=W)

broker_text = StringVar()
broker_label = Label(app, text='Broker IP: ', font=('bold', 12), pady=10)
broker_label.grid(row=11, column=0, sticky=W)
broker_entry = Entry(app, textvariable=broker_text)
broker_entry.grid(row=11, column=1)
# ID
ID_text = StringVar()
ID_label = Label(app, text='Client ID: ', font=('bold', 12), pady=10)
ID_label.grid(row=11, column=2, sticky=W)
ID_entry = Entry(app, textvariable=ID_text)
ID_entry.grid(row=11, column=3)

# user
user_text = StringVar()
user_label = Label(app, text='User: ', font=('bold', 12), pady=10)
user_label.grid(row=11, column=4, sticky=W)
user_entry = Entry(app, textvariable=user_text)
user_entry.grid(row=11, column=5)

# password
pass_text = StringVar()
pass_label = Label(app, text='Password: ', font=('bold', 12), pady=10)
pass_label.grid(row=11, column=6, sticky=W)
pass_entry = Entry(app, textvariable=pass_text)
pass_entry.grid(row=11, column=7)

# topic
topic_text = StringVar()
topic_label = Label(app, text='Topic: ', font=('bold', 12), pady=10)
topic_label.grid(row=12, column=0, sticky=W)
topic_entry = Entry(app, textvariable=topic_text)
topic_entry.grid(row=12, column=1)

# topic2
topic2_text = StringVar()
topic2_label = Label(app, text='Topic: ', font=('bold', 12), pady=10)
topic2_label.grid(row=13, column=0, sticky=W)
topic2_entry = Entry(app, textvariable=topic2_text)
topic2_entry.grid(row=13, column=1)

# topic2
payload_text = StringVar()
payload_label = Label(app, text='Payload: ', font=('bold', 12), pady=10)
payload_label.grid(row=13, column=2, sticky=W)
payload_entry = Entry(app, textvariable=payload_text)
payload_entry.grid(row=13, column=3)

# topic2
keepalive_text = IntVar()
keepalive_label = Label(app, text='Keepalive: ', font=('bold', 12), pady=10)
keepalive_label.grid(row=13, column=4, sticky=W)
keepalive_entry = Entry(app, textvariable=keepalive_text)
keepalive_entry.grid(row=13, column=5)

# topic2
patern_text = StringVar()
patern_label = Label(app, text='Message Pattern: ', font=('bold', 12), pady=10)
patern_label.grid(row=15, column=4, sticky=W)
patern_entry = Entry(app, textvariable=patern_text)
patern_entry.grid(row=15, column=5)

retain = BooleanVar()
retain_btn = Checkbutton(app, text="Retain", variable=retain, onvalue = True, offvalue = False,).grid(row=13, column=6)

clean = BooleanVar()
clean_btn = Checkbutton(app, text="Clean Session", variable=clean, onvalue = True, offvalue = False,).grid(row=12, column=2)


iat = Label(app, text='Inter Arrival ICMP Time: ', font=('bold', 14), pady=10)
iat.grid(row=14, column= 0, sticky=W)

sleep_time_txt1 = DoubleVar()
sleep_time_lbl1 = Label(app, text='Sleep time for 1 (in sec): ', font=('bold', 12), pady=10)
sleep_time_lbl1.grid(row=15, column= 0, sticky=W)
sleep_time_entry1 = Entry(app, textvariable=sleep_time_txt1)
sleep_time_entry1.grid(row=15, column=1)

sleep_time_txt0 = DoubleVar()
sleep_time_lbl0 = Label(app, text='Sleep time for 0: ', font=('bold', 12), pady=10)
sleep_time_lbl0.grid(row=15, column= 2, sticky=W)
sleep_time_entry0 = Entry(app, textvariable=sleep_time_txt0)
sleep_time_entry0.grid(row=15, column=3)

#SIP STEGO
sip_label = Label(app, text='SIP Packet: ', font=('bold', 14), pady=10)
sip_label.grid(row=16, column=0, sticky=W)

sip_ip_text = StringVar()
sip_ip_label = Label(app, text='Source IP: ', font=('bold', 12), pady=10)
sip_ip_label.grid(row=17, column=0, sticky=W)
sip_ip_entry = Entry(app, textvariable=sip_ip_text)
sip_ip_entry.grid(row=17, column=1)

sip_ipd_text = StringVar()
sip_ipd_label = Label(app, text='Destination IP: ', font=('bold', 12), pady=10)
sip_ipd_label.grid(row=17, column=2, sticky=W)
sip_ipd_entry = Entry(app, textvariable=sip_ipd_text)
sip_ipd_entry.grid(row=17, column=3)

callid_text = StringVar()
callid_label = Label(app, text='Call ID: ', font=('bold', 12), pady=10)
callid_label.grid(row=17, column=4, sticky=W)
callid_entry = Entry(app, textvariable=callid_text)
callid_entry.grid(row=17, column=5)

maxf_text = StringVar()
maxf_label = Label(app, text='Max Forward: ', font=('bold', 12), pady=10)
maxf_label.grid(row=17, column=6, sticky=W)
maxf_entry = Entry(app, textvariable=maxf_text)
maxf_entry.grid(row=17, column=7)

contact_text = StringVar()
contact_label = Label(app, text='Contact: ', font=('bold', 12), pady=10)
contact_label.grid(row=18, column=0, sticky=W)
contact_entry = Entry(app, textvariable=contact_text)
contact_entry.grid(row=18, column=1)

def cmd():
    print(dst_text.get())
    print(src_text.get())
    print(seq_text.get())
    print(id_text.get())
    cmd_ping(dst_text.get(), src_text.get(), seq_text.get(), id_text.get())

def icmp_time_stego():
    patern = patern_text.get()
    seq = seq_text.get()
    id =  id_text.get()
    for a in patern:
        print (a)
        cmd_ping(dst_text.get(), src_text.get(),seq,id)
        if a == '1':
            sleep(sleep_time_txt1.get())
        if a == '0':
            sleep(sleep_time_txt0.get())
        seq +=1


def cmd_TCP():
    print(dst_TCP_text.get())
    print(src_TCP_text.get())
    print(reserved_bits_text.get())
    print(seq_TCP_text.get())
    print(window_text.get())
    print(urgent_pointer_text.get())
    cmd_tcpip(src_TCP_text.get(), dst_TCP_text.get(), TOS_text.get(), ttl_text.get(), ip_id_text.get(),
              reserved_bits_text.get(), seq_TCP_text.get(), window_text.get(), urgent_pointer_text.get(),
              flags_text.get(),
              payload_text.get(), sport_text.get())

def cmd_mqtt_pub():
    mqtt_message(broker_text.get(), ID_text.get(), user_text.get(), pass_text.get(), topic2_text.get(),payload_text.get(),keepalive_text.get(),retain.get())


def cmd_mqtt():
    print("SUB top")
    mqtt_subscribe(broker_text.get(), ID_text.get(), user_text.get(), pass_text.get(), topic_text.get(),clean.get())

def cmd_sip():
    print("sip")
    sip_message(sip_ip_text.get(), sip_ipd_text.get() ,callid_text.get(), maxf_text.get(), contact_text.get())

# buttons
icmp_steg_btn = Button(app, text='Send Ping', width=12, command=cmd, padx=10)
icmp_steg_btn.grid(row=3, column=0)

# buttons
tcp_steg_btn = Button(app, text='Send TCP/IP', width=12, command=cmd_TCP, padx=10)
tcp_steg_btn.grid(row=9, column=0)

#MQTT buttons
mqtt_btn = Button(app, text='Subscribe', width=12, command=cmd_mqtt, padx=10)
mqtt_btn.grid(row=12, column=3)

mqtt_btn = Button(app, text='Publish', width=12, command=cmd_mqtt_pub, padx=10)
mqtt_btn.grid(row=13, column=7)

#TimeingStego
icmp_time_btn = Button(app, text='ICMP Time Stego', width=12, command=icmp_time_stego, padx=10)
icmp_time_btn.grid(row=15, column=7)

sip_btn = Button(app, text='Send SIP', width=12, command=cmd_sip, padx=10)
sip_btn.grid(row=18, column=2)

app.title('Stego Tester')
app.geometry('1200x800')
app.mainloop()
# cmd_tcpip("192.168.1.104")
# cmd_ping("192.168.1.104", 4, 128, 1, 0)
