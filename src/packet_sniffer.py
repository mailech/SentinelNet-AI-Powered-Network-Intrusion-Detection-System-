from scapy.all import sniff, IP
import requests
import random

BACKEND_URL = "http://127.0.0.1:5000/predict"


def process_packet(packet):

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        print(f"Packet: {src} → {dst}")

        # dummy features for ML model
        features = [random.randint(0,10) for _ in range(121)]

        try:

            response = requests.post(
                BACKEND_URL,
                json={"features": features}
            )

            result = response.json()

            print("Prediction:", result["prediction"])

        except:

            print("Backend not reachable")


def start_sniffing():

    print("SentinelNet Real-Time Monitoring Started...")

    sniff(prn=process_packet, store=False)


if __name__ == "__main__":

    start_sniffing()