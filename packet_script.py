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

def sip_message(ip_dst, ip_src, CallID, mf, contact, cseq):
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
    tos_num = TOS
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

if __name__ == "__main__":
    

    ip_src = "192.168.1.21"
    ip_dst = "192.168.1.1"
    TOS = 23
    ttl = 124
    id = 41241
    reserved = '0'
    seq_num = 1332132
    window = 1134
    src_port = 12356
    payload = "elo"
    flags = ''
    urg_ptr = "1"

    CallID = "hello"
    mf = "100"
    contact = "alice@sip.pl"


    messages = [#"10",
    #         "test"
             "Longer test.",
    #           "I want to be there."
    #            "Bar is a nice to place to hang out.",
    #            "Hello my name is TK, who are you?",
    #            "Dan ate the clouds like cotton candy.",
    #            "As the years pass by, we all know owners look more and more like their dogs.",
    #            "Yesterday I was on a trip and generally it was cool. Someday I want to go there again.",
    #            "She wasn't sure whether to be impressed or concerned that he folded t-shirts in.",
    #            "She wasn't sure whether to be impressed or concerned that he folded t-shirts in neat little packages.",
    #            "I'm troubleshooting a connection between a client PC and an HTTP server. In this example, the client is requesting a file and only receives a few KB before the connection is reset.",
    #            "This has all the tell tale signs of a MTU issue where the tunnel requires a smaller MTU but fails to learn that. A capture on the sending end should show the ICMP traffic giving this away.",
    #            "The real issue is to determine why the client, 192.168.120.105, is not responding to the larger TCP segment(s). Try to capture at 192.168.120.105, to verify if the server's larger TCP segment made it"
                ]
    for msg in messages:
        message = msg
        for char  in list(message):
            print (char)
            cseq =  str(ord(char))
            #seq_num = seq_num + 1
            #cmd_tcpip(ip_src, ip_dst, TOS, ttl, id, reserved, seq_num, window, urg_ptr, flags, payload, src_port)
            sip_message(ip_dst, ip_src, CallID, mf, contact, cseq)