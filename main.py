#!/user/bin/env python

import argparse
import scapy.all as scapy

def getting_input_from_user():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='ip', help='[-]The target Ip address')
    options = parser.parse_args()
    if not options.ip:
        parser.error('[!]Please enter an IP address')
    else:
        return options.ip


def scan(target):
    arp = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    for element in answered_list:
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(result_list):
    print("IP\t\t\tMac Address\n-----------------------------------------")
    for client in result_list:
        print(client['ip']+'\t\t'+client['mac'])

ip = getting_input_from_user()
scan_result = scan(ip)
print_result(scan_result)
