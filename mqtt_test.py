import paho.mqtt.client as mqtt
from time import sleep

client = mqtt.Client()
#client.on_connect = on_connect
#client.on_message = on_message
#client = mqtt.Client(id)
#client.username_pw_set(user, password=psw)
broker = "192.168.1.21"
payload = "test1"
topic = "test/topic"
print("connecting to broker ", broker)
client.connect(broker, 1883, True)
client.loop_start()
client.publish(topic, payload, retain=False)
client.loop_stop()
client.disconnect()