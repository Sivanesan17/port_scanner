from scapy.all import*
import socket


def check_network_connection():
	try:
		socket.create_connection(("www.google.com",80))	
		return True
	except OSError:
		return False

def port_scan(target,ports):
	print(f'Scanning target {target}')
	pkt=IP(dst=target)/TCP(dport=port,flags='S')
	resp=sr1(pkt,timeout=2,verbose=0)
	if resp is not None:
		if resp.haslayer(TCP) and resp.getlayer(TCP).flags==0x12:
			return True
		return False

#Check network Connection
if not check_network_connection():
	print("Please connect to a network to perform a port scan.")
	exit()


target=input("Enter a Target IP Address : ")
port_range=input("Enter Port Range to scan (e.g., 1-100): ")

start_port,end_port=map(int,port_range.split('-'))
for port in range(start_port,end_port+1):
	if port_scan(target,port):
		print(f"Port {port} is Open")
	else:
		print(f"Port {port} is closed or filtered")

