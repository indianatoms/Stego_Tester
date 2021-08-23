import paho.mqtt.client as mqtt
from time import sleep
client = mqtt.Client()

#client.on_connect = on_connect
#client.on_message = on_message
#client = mqtt.Client(id)

v = ["tk1","tk2","tk3","tk4","tk5","tk6","tk7","tk8","tk9","tk10"
    ,"tk1","tk2","tk3","tk4","tk5","tk6","tk7","tk8","tk9","tk10"]
ka = [1,2,3,4,5,6,7,8,9,1,2,3,4,56,7,89,9]
retain = [True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False,True,False]


for usr in v:
    user = usr
    psw = "du"
    broker = "192.168.1.21"
    payload = "test1"
    topic = "test/topic"
    print("connecting to broker ", broker)
    client.username_pw_set(user, password=psw)
    client.connect(broker, 1883)
    client.loop_start()
    client.publish(topic, payload, retain=False)
    client.loop_stop()
    client.disconnect()

