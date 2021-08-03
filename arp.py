#!/usr/bin/python3

# Скрипт принимает ARP запрос, затем создает такой же ARP-запрос, но от своего имени
# Затем ждет ответа две секунды. Если ответа не последовало, отправляет ответ от своего имени

import threading
import ipaddress
import argparse
from scapy.all import ARP, Ether, arping, sendp, conf, sniff, get_if_hwaddr
from pprint import pprint
from syslog import syslog

parser = argparse.ArgumentParser(description='Arp responder for non existent hosts')
parser.add_argument('iface', type=str, help='Interface name for listen on')
parser.add_argument('--debug', action="store_true", help='Debug mode, log all to stdout')
args = parser.parse_args()


def log(msg):
    if args.debug:
        print(msg)
    else:
        syslog(msg)


def handle_packet(packet):
    # Получен фрейм, в котором мой мак
    if packet.src == my_mac:
        return

    if packet['ARP'].op == 1: # who-has

        if str(packet.pdst).endswith('.1'):
            return

        if args.debug:
            log(f'{packet.pdst}: Received request, src-mac {packet.src}, iface {conf.iface}. Sending same request...')

        for i in range(1, 4):
            ans, unans = arping(packet.pdst)
            if ans: return

        log(f"{packet.pdst}: Requested by {packet.psrc}, {packet[Ether].src}")
        log(f"{packet.pdst}: There is no answer for my three requests. Sending fake answer on {conf.iface}")
        response = Ether()/ARP()
        response[Ether].dst = packet[Ether].src
        response[Ether].src = my_mac
        response[ARP].op = 2
        response[ARP].hwsrc = my_mac
        response[ARP].hwdst = packet[ARP].hwsrc
        response[ARP].psrc = packet[ARP].pdst
        response[ARP].pdst = packet[ARP].psrc
        sendp(response)
        log(f"{packet.pdst}: Done spoofing IP with my mac {my_mac} on {conf.iface}")


def aggregator(hash: str):
    # Нужно передать в функцию обработки пакета хэш, который она должна оброботать
    log(f"Start sniffing and answering on {conf.iface}, my mac is {my_mac}, hash {hash}")
    # Обработать пакет, только если hash совпадает
    sniff(filter="arp", lfilter=lambda packet: str(bin(int(ipaddress.IPv4Address(packet.pdst)))).endswith(hash), prn=handle_packet, store=0)


conf.verb = 0
conf.iface = args.iface
my_mac = get_if_hwaddr(conf.iface)

# Start 4 threads with hashes
for i in ['00', '01', '10', '11']:
    threading.Thread(target=aggregator, args=(i,)).start()

