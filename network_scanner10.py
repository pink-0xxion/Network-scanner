#!/usr/bin/env python
import scapy.all as scapy 
import argparse #using argparse instead of optparse

def get_arguments():
	parser = argparse.ArgumentParser() #here did the changes
	parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.") #here did the changes
	options = parser.parse_args() #parse_args() is same for both argparse and optparse BUT argparse return only options
	return options

def scan(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False) [0]
	
	clients_list = [] 
	for element in answered_list:
		client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
		clients_list.append(client_dict)
	return clients_list

def print_result(results_list): #another function for printing purpose
	print("IP\t\t\tMAC Address\n--------------------------------------------")
	for client in results_list: #here we iterating into BIG LIST
		print(client) #print in dictionary format
		print(client["ip"] + "\t\t" + client["mac"]) #print IP and MAC separately


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
