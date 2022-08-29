import re
import socket
import struct
import textwrap
import binascii
import struct
import sys
import json
import datetime
# from pyModbusTCP.client import ModbusClient

# TAB_1 = '\t - '
# TAB_2 = '\t\t - '
# TAB_3 = '\t\t\t - '
# TAB_4 = '\t\t\t\t - '

# DATA_TAB_1 = '\t   '
# DATA_TAB_2 = '\t\t   '
# DATA_TAB_3 = '\t\t\t   '
# DATA_TAB_4 = '\t\t\t\t   '

infile = r'/home/tango/Shafeek/sniffproj/modbuslogs.log'


def main():
    conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    filters = (["ICMP", 1, "ICMPv6"],["UDP", 17, "UDP"], ["TCP", 6, "TCP"])
    filter = []

    if len(sys.argv) == 2:
        print("This is the filter: ", sys.argv[1])
        for f in filters:
            if sys .argv[1] == f[0]:
                filter = f



    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 'IPV6':
            newPacket, nextProto = ipv6Header(data, filter)
            printPacketsV6(filter, nextProto, newPacket)

        elif eth_proto == 'IPV4':
            printPacketsV4(filter, data, raw_data)



def printPacketsV4(filter, data, raw_data):
    (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)

    # ICMP
    if proto == 1 and (len(filter) == 0 or filter[1] == 1):
        icmp_type, code, checksum, data = icmp_packet(data)
        print ("*******************ICMP***********************")
        print ("\tICMP type: %s" % (icmp_type))
        print ("\tICMP code: %s" % (code))
        print ("\tICMP checksum: %s" % (checksum))

    # TCP
    elif proto == 6 and (len(filter) == 0 or filter[1] == 6) and (src == '192.168.126.128' or src == '192.168.126.132'):
        print("\n*******************TCPv4***********************")
        print('Version: {}\tHeader Length: {}\tTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\tSource: {}\tTarget: {}'.format(proto, src, target))
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, window_size, checksum, urget_pointer = struct.unpack(
            '! H H L L H H H H', data[:20])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        # src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
        #     '! H H L L H H H H H H', raw_data[:24])
        print('\n*****TCP Segment*****')
        print('   - ' + 'Source Port: {}\tDestination Port: {}'.format(src_port, dest_port))
        print('   - ' + 'Sequence: {}\tAcknowledgment: {}'.format(sequence, acknowledgment))
        print('   - ' + '*****Flags*****')
        print('   - ' + 'URG: {}\tACK: {}\tPSH: {}'.format(flag_urg, flag_ack, flag_psh))
        print('   - ' + 'RST: {}\tSYN: {}\tFIN:{}'.format(flag_rst, flag_syn, flag_fin))
        print('   - ' + 'Window size: {}\tChecksum: {}\tUrgent Pointer: {}'.format(window_size, checksum, urget_pointer))
        data = data[offset:]

        if len(data) > 0:
            # HTTP
            if src_port == 80 or dest_port == 80:
                print('*****HTTP Data*****')
                try:
                    http = HTTP(data)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(str(line))
                except:
                    print(format_output_line("",data))
            elif src_port == 502 or dest_port == 502:
                print('   *****TCP Data*****')
                print(format_output_line("",data))
                #modbusproto(data)
            else:
                print('   *****TCP Data*****')
                print(format_output_line("",data))
                print(len(data))
                

    # UDP
    elif proto == 17 and (len(filter) == 0 or filter[1] == 17):
        print("*******************UDPv4***********************")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
        src_port, dest_port, length, data = udp_seg(data)
        print('*****UDP Segment*****')
        print('Source Port: {}\nDestination Port: {}\nLength: {}'.format(src_port, dest_port, length))


def printPacketsV6(filter, nextProto, newPacket):
    remainingPacket = ""

    if (nextProto == 'ICMPv6' and (len(filter) == 0 or filter[2] == "ICMPv6")):
        remainingPacket = icmpv6Header(newPacket)
    elif (nextProto == 'TCP' and (len(filter) == 0 or filter[2] == "TCP")):
        remainingPacket = tcpHeader(newPacket)
    elif (nextProto == 'UDP' and (len(filter) == 0 or filter[2] == "UDP")):
        remainingPacket = udpHeader(newPacket)

    return remainingPacket


def tcpHeader(newPacket):
    # 2 unsigned short,2unsigned Int,4 unsigned short. 2byt+2byt+4byt+4byt+2byt+2byt+2byt+2byt==20byts
    packet = struct.unpack("!2H2I4H", newPacket[0:20])
    srcPort = packet[0]
    dstPort = packet[1]
    sqncNum = packet[2]
    acknNum = packet[3]
    dataOffset = packet[4] >> 12
    reserved = (packet[4] >> 6) & 0x003F
    tcpFlags = packet[4] & 0x003F 
    urgFlag = tcpFlags & 0x0020 
    ackFlag = tcpFlags & 0x0010 
    pushFlag = tcpFlags & 0x0008  
    resetFlag = tcpFlags & 0x0004 
    synFlag = tcpFlags & 0x0002 
    finFlag = tcpFlags & 0x0001 
    window = packet[5]
    checkSum = packet[6]
    urgPntr = packet[7]

    print ("*******************TCP***********************")
    print ("\tSource Port: "+str(srcPort) )
    print ("\tDestination Port: "+str(dstPort) )
    print ("\tSequence Number: "+str(sqncNum) )
    print ("\tAck. Number: "+str(acknNum) )
    print ("\tData Offset: "+str(dataOffset) )
    print ("\tReserved: "+str(reserved) )
    print ("\tTCP Flags: "+str(tcpFlags) )

    if(urgFlag == 32):
        print ("\tUrgent Flag: Set")
    if(ackFlag == 16):
        print ("\tAck Flag: Set")
    if(pushFlag == 8):
        print ("\tPush Flag: Set")
    if(resetFlag == 4):
        print ("\tReset Flag: Set")
    if(synFlag == 2):
        print ("\tSyn Flag: Set")
    if(finFlag == True):
        print ("\tFin Flag: Set")

    print ("\tWindow: "+str(window))
    print ("\tChecksum: "+str(checkSum))
    print ("\tUrgent Pointer: "+str(urgPntr))
    print (" ")

    packet = packet[20:]
    return packet


def udpHeader(newPacket):
    packet = struct.unpack("!4H", newPacket[0:8])
    srcPort = packet[0]
    dstPort = packet[1]
    lenght = packet[2]
    checkSum = packet[3]

    print ("*******************UDP***********************")
    print ("\tSource Port: "+str(srcPort))
    print ("\tDestination Port: "+str(dstPort))
    print ("\tLenght: "+str(lenght))
    print ("\tChecksum: "+str(checkSum))
    print (" ")

    packet = packet[8:]
    return packet


def icmpv6Header(data):
    ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_chekcsum = struct.unpack(
        ">BBH", data[:4])

    print ("*******************ICMPv6***********************")
    print ("\tICMPv6 type: %s" % (ipv6_icmp_type))
    print ("\tICMPv6 code: %s" % (ipv6_icmp_code))
    print ("\tICMPv6 checksum: %s" % (ipv6_icmp_chekcsum))

    data = data[4:]
    return data


def nextHeader(ipv6_next_header):
    if (ipv6_next_header == 6):
        ipv6_next_header = 'TCP'
    elif (ipv6_next_header == 17):
        ipv6_next_header = 'UDP'
    elif (ipv6_next_header == 43):
        ipv6_next_header = 'Routing'
    elif (ipv6_next_header == 1):
        ipv6_next_header = 'ICMP'
    elif (ipv6_next_header == 58):
        ipv6_next_header = 'ICMPv6'
    elif (ipv6_next_header == 44):
        ipv6_next_header = 'Fragment'
    elif (ipv6_next_header == 0):
        ipv6_next_header = 'HOPOPT'
    elif (ipv6_next_header == 60):
        ipv6_next_header = 'Destination'
    elif (ipv6_next_header == 51):
        ipv6_next_header = 'Authentication'
    elif (ipv6_next_header == 50):
        ipv6_next_header = 'Encapsuling'

    return ipv6_next_header


def ipv6Header(data, filter):
    ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack(
        ">IHBB", data[0:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    bin(ipv6_first_word)
    "{0:b}".format(ipv6_first_word)
    version = ipv6_first_word >> 28
    traffic_class = ipv6_first_word >> 16
    traffic_class = int(traffic_class) & 4095
    flow_label = int(ipv6_first_word) & 65535

    ipv6_next_header = nextHeader(ipv6_next_header)
    data = data[40:]

    return data, ipv6_next_header


# Unpack Ethernet Frame
def ethernet_frame(data):
    proto = ""
    IpHeader = struct.unpack("!6s6sH",data[0:14])
    dstMac = binascii.hexlify(IpHeader[0]) 
    srcMac = binascii.hexlify(IpHeader[1]) 
    protoType = IpHeader[2] 
    nextProto = hex(protoType) 

    if (nextProto == '0x800'): 
        proto = 'IPV4'
    elif (nextProto == '0x86dd'): 
        proto = 'IPV6'

    data = data[14:]

    return dstMac, srcMac, proto, data

    # Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks for any TCP Packet
def tcp_seg(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >> 4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats the output line
def format_output_line(prefix, string):
    size=80
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2 == 0:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def modbusproto(data):
    modlog = {}
    #modlog['TimeStamp'] = datetime.datetime.now()
    print("   **********************ModBus/TCP**********************")
    (T_id, Proto, length, unit_id, func) = struct.unpack('!HHHBB', data[:8])
    print("\tTransaction ID: {}\tProtocol: {}\n\tLength: {}\tUnit Address: {}\
    \n        *************ModBus*************\n \tFunction: {}".format(
        T_id, Proto, length, unit_id, func), )
    modlog['Tran_ID'], modlog['Protocol'], modlog['Length'], modlog['Unit_ID'], modlog['func'] = T_id, Proto, length, unit_id, func
    
    if func == 1:
        modlog['Coil Address'], modlog['No. of Coils'] = read_coils(data[8:])
    elif func == 2:
        modlog['Discrete Input Address'], modlog['No. of Discrete Inputs'] = read_discrete_inputs(data[8:])
    elif func == 3:
        modlog['Holding Register Address'], modlog ['No. of holding registers'] = read_holding_registers(data[8:])
    elif func == 4:
        modlog['Input Register Address'], modlog['No. of input registers'] = read_input_registers(data[8:])
    elif func == 5:
        modlog['Coil Address'], modlog['Data'] = write_coil(data[8:])
    elif func == 6:
        (modlog['Register Address'], modlog['Data']) = write_register(data[8:])
    elif func == 15:
        modlog['Coil Address'], modlog['No. of Coils'], modlog['No. of bytes of coil value'], \
            modlog['Coil values (8 coil values per byte)'] = write_multiple_coils(data[8:])
    elif func == 16:
        modlog['Register Address'], modlog['No. of Registers'], modlog['DataCount'], modlog['Data'] = write_multiple_registers(data[8:])
    
    writelog(infile, modlog)

def read_coils(data):
    (coil_addr, no_of_coils) = struct.unpack('! H H', data)
    print('\tCoil Address: {}\tNo. of Coils: {}'.format(coil_addr, no_of_coils))
    return coil_addr, no_of_coils

def read_discrete_inputs(data):
    (dicrete_addr, no_of_discrete) = struct.unpack('! H H', data)
    print('\tDiscrete Input Address: {}\tNo. of Discrete Inputs: {}'.format(dicrete_addr, no_of_discrete))
    return dicrete_addr, no_of_discrete

def read_holding_registers(data):
    (reg_addr, no_of_registers) = struct.unpack('! H H', data)
    print('\tHolding Register Address: {}\tNo. of holding registers: {}'.format(reg_addr, no_of_registers))
    return reg_addr, no_of_registers

def read_input_registers(data):
    (reg_addr, no_of_registers) = struct.unpack('! H H', data)
    print('\tInput Register Address: {}\tNo. of input registers: {}'.format(reg_addr, no_of_registers))
    return reg_addr, no_of_registers

def write_coil(data):
    (coil_addr, data) = struct.unpack('! H H', data)
    print('\tCoil Address: {}\tData: {}'.format(coil_addr, data))
    return coil_addr, data

def write_register(data):
    (reg_addr, data) = struct.unpack('! H H', data)
    print('\tRegister Address: {}\tData: {}'.format(reg_addr, data))
    return reg_addr, data
    

def write_multiple_coils(data):
    (coil_addr, no_of_coils, no_of_bytes_of_coil_value) = struct.unpack('! H H B', data[:5])
    print('\tCoil Address: {}\tNo. of Coils: {}\n\tNo. of bytes of coil value: {}'.format(
        coil_addr, no_of_coils, no_of_bytes_of_coil_value))
    print('\tCoil values (8 coil values per byte): {}'.format(struct.unpack('! {}'.format(
        "B"*no_of_bytes_of_coil_value), data[5:])))
    return coil_addr, no_of_coils, no_of_bytes_of_coil_value, struct.unpack('! {}'.format("B"*no_of_bytes_of_coil_value), data[5:])

def write_multiple_registers(data):
    (reg_addr, no_of_registers, data_count) = struct.unpack('! H H B', data[:5])
    print('\tRegister Address: {}\tNo. of Registers: {}\t DataCount: {}'.format(reg_addr, 
        no_of_registers, int(data_count/2)))
    print('\tData: {}'.format(struct.unpack('! {}'.format("H"*int(data_count/2)), data[5:])))
    return reg_addr, no_of_registers, int(data_count/2), struct.unpack('! {}'.format("H"*int(data_count/2)), data[5:])

def writelog(infile, data):
    with open(infile, "a+") as modbuslog:
        # for line in modbuslog:
            # doc = line[21:]
            modbuslog.write(json.dumps(data) + '\n')
main()
