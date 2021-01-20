import json
import base64
import binascii

from scapy.all import *

import p4runtime_sh.shell as sh

services=[]
access_list=[]

MIN_SPA_DATA_SIZE = 80
MAX_SPA_PACKET_LEN = 1500
B64_RIJNDAEL_SALT = "U2FsdGVkX1"
B64_RIJNDAEL_SALT_STR_LEN = 10
FKO_SDP_ID_SIZE = 4


class service:
    def __init__(self, s_id, proto, port, nat_ip, nat_port):
        self.service_id = s_id
        self.proto = proto
        self.port = port
        self.nat_ip = nat_ip
        self.nat_port = nat_port

class access:
    def __init__(self, sdp_id, service_list, open_ports, spa_encryption_key_base64, spa_hmac_key_base64):
        self.sdp_id = sdp_id
        self.source = "ANY"
        self.service_list = service_list
        self.open_ports = open_ports
        self.spa_encryption_key_base64 = spa_encryption_key_base64
        self.spa_hmac_key_base64 = spa_encryption_key_base64

class spa_packet:
    def __init__(self, spa_pkt):
        self.packet_proto = "temp"
        self.packet_src_ip = "temp"
        self.packet_dst_ip = "temp"
        self.packet_src_port = "temp"
        self.packet_dst_port = "temp"
        self.sdp_id = 0
        self.sdp_id_str = "0"
        self.packet_data = spa_pkt
        self.packet_data_len = len(self.packet_data) # TODO definisci in base a tipo formato


# TODO class spa_pkt_info:

# TODO ora rules fisse, implementa modifica dinamica in base agli accessi consentiti
def writeFirewallRules(egress_port,
                     dst_eth_addr, dst_ip_addr):

    te = sh.TableEntry('MyIngress.ipv4_lpm')(action = 'MyIngress.ipv4_forward')
    te.match['hdr.ipv4.dstAddr'] = (dst_ip_addr)
    te.action['dstAddr'] = (dst_eth_addr)
    te.action['port'] = (egress_port)
    te.insert()
    
    # print "Installed table rule to IP ", dst_ip_addr ," forwarding to switch port ", egress_port


def parse_service_json():
    # extracting JSON for gateway service
    with open("services.json", "r") as sj:
        s_json = json.load(sj)
        # print "Loaded this new service json: "
        # print s_json
        curr_s_id = int(s_json.get(u'service_id'))
        curr_proto = s_json.get(u'proto')
        curr_port = s_json.get(u'port')
        curr_nat_ip = s_json.get(u'nat_ip')
        curr_nat_port = s_json.get(u'nat_port')
        services.append(service(curr_s_id, curr_proto, curr_port, curr_nat_ip, curr_nat_port))
        # print "added service id ", services[0].service_id, " to the services list"

def parse_access_json():

    # extracting JSON for authorized users
    
    with open("access_3.json", "r") as aj:
        a_json = json.load(aj)
        # print "Loaded this new access json: "
        # print a_json
        curr_sdp_id = int(a_json.get(u'sdp_id'))
        curr_s_list = a_json.get(u'service_list')
        # print curr_s_list
        curr_ports = a_json.get(u'open_ports')
        curr_enc_key = a_json.get(u'spa_encryption_key_base64')
        curr_hmac_key = a_json.get(u'spa_hmac_key_base64')
        access_list.append(access(curr_sdp_id, curr_s_list, curr_ports, curr_enc_key, curr_hmac_key))
        # print "added access for sdp id ", access_list[0].sdp_id, " to the service/s ", access_list[0].service_list, " w.r.t. this/these port/s ", access_list[0].open_ports
        
def constant_runtime_cmp(a, b, len):

    good = 0;
    bad  = 0;

    for x in range(len):
        if a[x] == b[x]:
            good += 1
        else:
            bad += 1

    if good == len:
        return 0
    else:
        return 0 - bad

def is_base64(buf, len):

    rv = 1

    for i in range(len):
    
        if not (buf[i].isalnum() or buf[i] == '/' or buf[i] == '+' or buf[i] == '='):
        
            rv = 0
            break

    return rv


def parse_spa_packet(spa_message):
    # TODO extract ip s/d, port d/d, data parmeters from spa_message
    spa_obj = spa_packet(spa_message)

    if spa_obj.packet_data_len > MAX_SPA_PACKET_LEN:
        # print "packet exceed max SPA"
        return # TODO not spa message

    if spa_obj.packet_data_len < MIN_SPA_DATA_SIZE:
        # print "packet too small"
        return # TODO not spa message

    # verify no rijndael prefix
    if constant_runtime_cmp(spa_obj.packet_data, B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN) == 0:
        # print "packet is forged"
        return # SPA_MSG_BAD_DATA

    # verify if base64 encoding
    if not is_base64(spa_obj.packet_data, spa_obj.packet_data_len):
        # print "packet has invalid characters"
        return #SPA_MSG_NOT_SPA_DATA
    
    # extract encoded sdp id
    encoded_sdp_id = spa_obj.packet_data[:6]
    # print "Encoded SDP ID extracted ", encoded_sdp_id 

    encoded_sdp_id += "=" * ((4 - len(encoded_sdp_id) % 4) % 4)
    # print "Encoded SDP ID padded ", encoded_sdp_id 
    # decode from b64 to original data
    decoded_sdp_id = base64.b64decode(encoded_sdp_id)
    # TODO SDP ID, ora stringa, farlo diventare int
    # print "Decoded SDP ID is: ", decoded_sdp_id, type(decoded_sdp_id)

    spa_obj.sdp_id = decoded_sdp_id
    # print "SDP ID inserted in spaobj as: ", spa_obj.sdp_id

    # TODO make a string version too
    # in C is : sn# printf(spa_pkt->sdp_id_str, MAX_SDP_ID_STR_LEN, "%"PRIu32, sdp_id);

def main():
    # print "main execution"
    
    # gateway switch definition
    sh.setup(
        device_id=1,
        grpc_addr='0.0.0.0:50051',
        election_id=(0, 1), # (high, low)
        config=sh.FwdPipeConfig('build/switch.p4.p4info.txt', 'build/switch.json')
    )

    # print "switch defined and configured"
    
    # Writing startup table rules
    
    writeFirewallRules(egress_port=0, dst_eth_addr="08:00:27:c1:60:c1", dst_ip_addr="192.168.1.11")
    
    writeFirewallRules(egress_port=1, dst_eth_addr="08:00:27:cc:9a:c9", dst_ip_addr="192.168.2.22")
    
    writeFirewallRules(egress_port=1, dst_eth_addr="08:00:27:cc:9a:c9", dst_ip_addr="192.168.4.44")
    
    writeFirewallRules(egress_port=2, dst_eth_addr="08:00:27:88:f8:9b", dst_ip_addr="192.168.3.33")

    # SPA packet load and analysis
    packet = rdpcap('SPA_PACKET.pcap')
    # print packet
    for p in packet:
        payload = p[UDP].payload.load
        # print type(payload), payload
        parse_spa_packet(payload)

if __name__ == "__main__":
    main()
