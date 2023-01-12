import socket
from struct import *
import binascii
import argparse
import os

port_file_path = ''
local_ip = socket.gethostbyname(socket.gethostname())
target_ip = ''

class Packet:
    def __init__(self, src_ip, dest_ip, dest_port):
        # https://docs.python.org/3.7/library/struct.html#format-characters
        # all values need to be at least one byte long (-> we need to add up some values)

        ############
        # IP segment
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset
        
        #############
        # TCP segment
        self.src_port = 0x3039
        self.dest_port = dest_port      
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin
        
        ########
        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""
       
       
    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i+1] 
            s = s + w
        # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

        
    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                          self.identification, self.f_fo,
                                          self.ttl, self.protocol, self.header_checksum,
                                          self.src_addr,
                                          self.dest_addr)
        return tmp_ip_header


    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                       self.seq_no,
                                       self.ack_no,
                                       self.data_offset_res_flags, self.window_size,
                                       self.checksum, self.urg_pointer)
        return tmp_tcp_header


    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                                self.identification, self.f_fo,
                                                self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                                                self.src_addr,
                                                self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol, len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                             self.seq_no,
                                             self.ack_no,
                                             self.data_offset_res_flags, self.window_size,
                                             self.calc_checksum(psh), self.urg_pointer)
        
        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header

        
    def send_packet(self, timeout):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(self.packet, (self.dest_ip, 0))
        s.settimeout(timeout)
        data = None
        try:
            data = s.recv(1024)
        except:
            pass
        s.close()
        return data
        
    

# could work with e.g. struct.unpack() here
# however, lazy PoC (012 = [SYN ACK]), therefore:
def check_if_open(port, response):
    if response is None:
        print("Port "+str(port)+" is: closed")
    else:
        cont = binascii.hexlify(response)
        if cont[65:68] == b"012":
            print("Port "+str(port)+" is: open")
        else:
            print("Port "+str(port)+" is: closed")

def create_parser():
    parser = argparse.ArgumentParser(description='A port scanner which preform a SYN scan')
    parser.add_argument('--ip', type=str, default='', required=True, help='The target IP (required)')
    parser.add_argument('-f', '--file', type=str, default='', help='File containing port numbers')
    parser.add_argument('-p', '--ports', type=str, default='', help='Ports range to scan')
    parser.add_argument('--exclude-ports', dest='exclude', type=str, default='', help='Ports to exclude from scan (default is the top scanned ports)')
    parser.add_argument('-t0',dest='t0', action='store_true', help='Setting a timeout for the scan (Paranoid: 300 seconds)')
    parser.add_argument('-t1',dest='t1', action='store_true', help='Setting a timeout for the scan (Sneaky: 15 seconds)')
    parser.add_argument('-t2',dest='t2', action='store_true', help='Setting a timeout for the scan (Normal: 1 seconds)')
    parser.add_argument('-t3',dest='t3', action='store_true', help='Setting a timeout for the scan (Aggressive: 0.5 seconds)')
    parser.add_argument('-t4',dest='t4', action='store_true', help='Setting a timeout for the scan (Insane: 0.25 seconds)')
    args = parser.parse_args()

    return args

def create_port_list(s_port, e_port):
    return list(range(s_port, e_port + 1))

def exclude_ports(ports_list_to_exclude, original_list):
    for port in ports_list_to_exclude:
        if port in original_list:
            original_list.remove(port)

    return original_list

def main():
    args = create_parser()
    timeout = 1

    ports_list = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    # check file specifications
    if args.file != '':
        if os.path.isfile(args.file) == False:
            print("[!] Error: f: path is not a file")
            exit()
            
        ports_list = []
        with open(args.file, "r") as ports_file:
            for port_line in ports_file:
                if port_line.rstrip().isnumeric():
                    if int(port_line) > 65535:
                        print("[!] Error: port number in file out of range")
                        exit()
                    else:
                        ports_list.append(int(port_line.rstrip()))
                else:
                    print("[!] Error: non port number found in file")
                    exit()

    try:
        socket.inet_aton(args.ip)
    except socket.error:
        print("[!] Error: t: target ip is not a valid ip")
        exit()
        
    target_ip = args.ip

    if args.t0:
        timeout = 300
    
    if args.t1:
        timeout = 15
        
    if args.t2:
        timeout = 1
        
    if args.t3:
        timeout = 0.5

    if args.t4:
        timeout = 0.25

    # check range specifications
    if args.ports != '':
        port_range = args.ports.split("-")
        try:
            if port_range[0].isnumeric() and port_range[1].isnumeric():
                if int(port_range[0]) > int(port_range[1]) or int(port_range[1]) > 65535:
                    print("[!] Error: p: port range invalid")
                    exit()
                else:
                    ports_list = create_port_list(int(port_range[0]), int(port_range[1]))
            else:
                print("[!] Error: p: port range invalid")
                exit()

        except IndexError:
            print("[!] Error: p: port range invalid")
            exit()

    if args.exclude != '':
        port_range = args.exclude.split("-")
        try:
            if port_range[0].isnumeric() and port_range[1].isnumeric():
                if int(port_range[0]) > int(port_range[1]) or int(port_range[1]) > 65535:
                    print("[!] Error: p: port range invalid")
                    exit()
                else:
                    to_exclude_list = list(range(int(port_range[0]), int(port_range[1])+1))
                    ports_list = exclude_ports(to_exclude_list, ports_list)
            else:
                print("[!] Error: p: port range invalid")
                exit()

        except IndexError:
            print("[!] Error: p: port range invalid")
            exit()

    print(ports_list)

    print("[+] Scanning...")
    for port in ports_list:
        packet_sent = Packet(local_ip, target_ip, port)
        packet_sent.generate_packet()
        result = packet_sent.send_packet(timeout)
        check_if_open(port, result)

if __name__ == '__main__':
    main()