import socket
import ssl
import struct
import os
import json
import shutil
import datetime as dt
import threading
import base64
import binascii
import hmac

from scapy.all import *
from hashlib import sha256
from scapy.layers.l2 import Ether

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES


import p4runtime_sh.shell as sh
from p4.config.v1 import p4info_pb2
from p4.v1 import p4runtime_pb2

ca_file = os.path.join(os.sys.path[0], "Certs/ca.crt")
certfile = os.path.join(os.sys.path[0], "Certs/2.crt")
keyfile = os.path.join(os.sys.path[0], "Certs/2.key")

# SDP sonstants
SDP_COM_MAX_MSG_BLOCK_LEN = 16384
SDP_MSG_MIN_LEN = 22
CRED_UPDATE_INTERVAL = 7200
SERVICE_REFRESH_INTERVAL = 86400
ACCESS_REFRESH_INTERVAL = 86400
DEFAULT_INTERVAL_KEEP_ALIVE_SECONDS =10

# SPA constants
MIN_SPA_DATA_SIZE = 80
MAX_SPA_PACKET_LEN = 1500
B64_RIJNDAEL_SALT = "U2FsdGVkX1"
B64_RIJNDAEL_SALT_STR_LEN = 10
FKO_SDP_ID_SIZE = 4
SHA256_B64_LEN = 43
RIJNDAEL_BLOCKSIZE = 16

# Global variables
controller_ready = 0
last_cred_update = dt.datetime(1967, 1, 1)
last_service_refresh = dt.datetime(1967, 1, 1)
last_access_refresh = dt.datetime(1967, 1, 1)
last_contact = dt.datetime(1967, 1, 1)
client_state = "ready"
services = []
access_list = []
digest_list=[]

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
        self.spa_hmac_key_base64 = spa_hmac_key_base64

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
        self.message = spa_pkt
        self.message_len = len(self.message)

# ___*** util. functions ***___

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
        if not (buf[i:i+1].isalnum() or buf[i:i+1].decode() == '/' or buf[i:i+1].decode() == '+' or buf[i:i+1].decode() == '='):
            rv = 0
            break
    return rv
    
def add_padding(word):
    padd = (4 - len(word) % 4) % 4
    for i in range(padd):
        word = bytearray(word)
        word.extend('='.encode('latin-1'))
    return word


# ___*** simple_switch_grpc functions ***___

def writeFirewallRules(egress_port, dst_eth_addr, dst_ip_addr):
    # TODO ora rules fisse, implementa modifica dinamica in base agli accessi consentiti
    te = sh.TableEntry('MyIngress.ipv4_lpm')(action = 'MyIngress.ipv4_forward')
    te.match['hdr.ipv4.dstAddr'] = (dst_ip_addr)
    te.action['dstAddr'] = (dst_eth_addr)
    te.action['port'] = (egress_port)
    te.insert()
    
    print("Installed table rule to IP " + str(dst_ip_addr) + " forwarding to switch port " + str(egress_port))


# ___*** SPA functions ***___

def parse_spa_packet(spa_message, source, destination):
    # TODO extract ip s/d, port d/d, data parmeters from spa_message
    spa_obj = spa_packet(spa_message)
    spa_obj.packet_proto = "UDP"
    spa_obj.packet_src_ip = source
    spa_obj.packet_dst_ip = destination

    if spa_obj.packet_data_len > MAX_SPA_PACKET_LEN:
        print("[SPA] packet exceed max SPA")
        return # TODO not spa message

    if spa_obj.packet_data_len < MIN_SPA_DATA_SIZE:
        print("[SPA] packet too small")
        return # TODO not spa message
        
    print("[SPA] SPA message is of the right size")

    # verify no rijndael prefix
    if constant_runtime_cmp(spa_obj.packet_data, B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN) == 0:
        print("[SPA] packet is forged")
        return # SPA_MSG_BAD_DATA
        
    print("[SPA] SPA message has no forged prefix")

    # verify if base64 encoding
    if not is_base64(spa_obj.packet_data, spa_obj.packet_data_len):
        print("[SPA] packet has invalid characters")
        return #SPA_MSG_NOT_SPA_DATA
        
    print("[SPA] SPA message is base64")
    
    # extract encoded sdp id
    encoded_sdp_id = spa_obj.packet_data[:6]
    print("[SPA] Encoded SDP ID extracted " + encoded_sdp_id.decode())
    
    padd = (4 - len(encoded_sdp_id) % 4) % 4
    for i in range(padd):
        encoded_sdp_id = bytearray(encoded_sdp_id)
        encoded_sdp_id.extend('='.encode('latin-1'))
    print("[SPA] Encoded SDP ID padded " + encoded_sdp_id.decode())
    
    # decode from b64 to original data
    decoded_sdp_id = (base64.b64decode(encoded_sdp_id))
    print("[SPA] Decoded SDP ID is: " + decoded_sdp_id.decode())
    print(type(decoded_sdp_id))
    
    spa_obj.sdp_id = int.from_bytes(decoded_sdp_id, "little")
    print("[SPA] SDP ID inserted in spaobj as: " + str(spa_obj.sdp_id))
    print(type(spa_obj.sdp_id))

    if (spa_obj.sdp_id == 0):
        return # SPA_MSG_BAD_DATA
    
    #replay check: fai SHA256 converti in base64, compara con archivio digest e salva
    m = hashlib.sha256()
    m.update(spa_obj.packet_data)
    curr_digest = base64.b64encode(m.digest())
    print("[SPA] SPA messgage B64 digested is: " + str(curr_digest))
    for i in digest_list:
        if i == curr_digest:
            print("[SPA] FOUND SAME DIGEST, REPLAY ATTACK!")
            return #REPLAY_ATTACK_ERR
    digest_list.append(curr_digest)
    print("[SPA] Digest saved, current archive is:")
    print(digest_list)

    #SDP ID check
    for a in access_list:
        if a.sdp_id == spa_obj.sdp_id:
            print("[SPA] Match found for the SDP ID in access database")
            curr_stanza = a
            break
        else:
            print("[SPA] Not an authorized SDP ID")
            return #SPA_FROM_UNAUTH_SDPID

    #IMPLEMENT IP CHECK (current ANY)

    #CHECK ENCRYPTION TYPE: we work only with Rijndael

    #HMAC DIGEST
    hmac_digest_b64 = spa_obj.packet_data[-SHA256_B64_LEN:]
    hmac_digest_b64_padded = add_padding(hmac_digest_b64)
    hmac_digest = base64.b64decode(hmac_digest_b64_padded)

    tbuf = spa_obj.packet_data[:-SHA256_B64_LEN]

    key_b64 = bytes(curr_stanza.spa_hmac_key_base64 , 'latin-1')
    key = base64.b64decode(key_b64)

    h = hmac.new(key, tbuf, hashlib.sha256)
    curr_digest = h.digest()

    print("[SPA] Extracted HMAC is")
    print(hmac_digest)
    print("[SPA] Calculated HMAC is")
    print(curr_digest)

    if (constant_runtime_cmp(hmac_digest, curr_digest, len(hmac_digest)) != 0):
        print("[SPA] HMAC verification failed")
        return # INVALID_DATA_HMAC_COMPAREFAIL

    # ** HMAC verified, remove SDP_ID from message and HMAC
    message_b64 = bytes(B64_RIJNDAEL_SALT, 'latin-1') + spa_obj.packet_data[6:-SHA256_B64_LEN]
    message_b64 = add_padding(message_b64)
    message_len_b64 = len(message_b64)
    spa_obj.message_data = base64.b64decode(message_b64)
    spa_obj.message_data_len = len(spa_obj.message_data)

    # ** Message decryption
    if((spa_obj.message_data_len % RIJNDAEL_BLOCKSIZE) != 0):
        print("[SPA] wrong cipher size!")
        return
    salt = spa_obj.message_data[8:16]
    ciphertext = spa_obj.message_data[16:]
    password = base64.b64decode(curr_stanza.spa_encryption_key_base64)
    key_len = 32
    iv_len = 16
    
    dtot =  md5(password + salt).digest()
    d = [ dtot ]
    while len(dtot)<(iv_len+key_len):
        d.append( md5(d[-1] + password + salt).digest() )
        dtot += d[-1]
        
    key = dtot[:key_len]
    iv = dtot[key_len:key_len+iv_len]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), 16)
    
    print("[SPA] SPA message is decrypted! Content is: " + str(decrypted))
    
    # TODO check su parametri dati
    # decrypted dev'essere di dimensione > len(cipher) - 32
    # Make sure there are no non-ascii printable chars
    # Make sure there are enough fields in the SPA packet delimited with ':' chars
    
    # ** Parsing
    fields = decrypted.split(b':')
    digest = fields.pop()
    tbuf = decrypted[:-(len(digest)+1)]
    
    # verify digest
    s = hashlib.sha256()
    s.update(tbuf)
    curr_digest = base64.b64encode(s.digest())
    digest_pad = add_padding(digest)
    if (constant_runtime_cmp(digest_pad, curr_digest, len(digest_pad)) != 0):
        print("[SPA] Digest verification failed")
        return # DIGEST_VERIFICATION_FAILED
    print("[SPA] Digest verified")
        
    # message
    msg = base64.b64decode(add_padding(fields[3]))
    msg = msg.split(b',')
    spa_ip = msg[0]
    service_req = []
    allowed_serv = []
    for s in range(1, len(msg)):
        service_req.append(msg[s])
    print("[SPA] receive SPA message from IP " + str(spa_ip) + " for services " + str(service_req))
    
    # TODO Verifica TimeOut check_pkt_age in incoming_spa
    
    for a in access_list:
        if a.sdp_id == spa_obj.sdp_id:
            a_services = a.service_list.split(", ")
            for s in a_services:
                for r in service_req:
                    r = r.decode("utf-8")
                    if s == r:
                        allowed_serv.append(r)
    
    if not allowed_serv:
        print("[SPA] SDP ID is not authorized for any service")
        return #SPA_FROM_UNAUTH_SDPID
            
    print("[SPA] SDP ID " + str(spa_obj.sdp_id) + " is allowed to access service/s: " + str(allowed_serv))

    return
    # TODO implementa valori return

# ___*** SDP functions ***___

def send_message(curr_sock, action, data):
    tmp = {}
    tmp['action'] = action
    jout_msg = json.dumps(tmp)
    s_bytes = bytes(jout_msg,encoding="utf-8")
    print("Sending message " + str(jout_msg))
    msg_len = len(s_bytes)
    print("Bytes sent:" + str(msg_len))
    msg_len = struct.pack('!i', msg_len)
    curr_sock.sendall(msg_len)
    curr_sock.sendall(bytes(s_bytes))

def cred_update_req(curr_sock, server_info, msg_cnt):
    if (dt.datetime.now() >= last_cred_update + dt.timedelta(seconds=CRED_UPDATE_INTERVAL)):
        print("It is time for a credential update request.")
        send_message(curr_sock,'credential_update_request',None)
        client_state = "cred_update"
        check_inbox(msg_cnt, 1, curr_sock, server_info)
        
def serv_refresh_req(curr_sock, server_info, msg_cnt):
    if (dt.datetime.now() >= last_service_refresh + dt.timedelta(seconds=SERVICE_REFRESH_INTERVAL)):
        print("It is time for a service refresh request.")
        send_message(curr_sock,'service_refresh_request',None)
        client_state = "service_update"
        check_inbox(msg_cnt, 1, curr_sock, server_info)
        
def access_refresh_req(curr_sock, server_info, msg_cnt):
    if (dt.datetime.now() >= last_access_refresh + dt.timedelta(seconds=ACCESS_REFRESH_INTERVAL)):
        print("It is time for aa access refresh request.")
        send_message(curr_sock,'access_refresh_request',None)
        client_state = "access_update"
        check_inbox(msg_cnt, 1, curr_sock, server_info)
        
def keep_alive_req(curr_sock, server_info, msg_cnt):
    if (dt.datetime.now() >= last_contact + dt.timedelta(seconds=DEFAULT_INTERVAL_KEEP_ALIVE_SECONDS)):
        print("Sensing keepalive.")
        send_message(curr_sock,'keep_alive',None)
        client_state = "keep_alive"
        check_inbox(msg_cnt, 1, curr_sock, server_info)

def check_inbox(cnt, queue_len, curr_sock, server_info):

    global controller_ready
    global encryption_key
    global hmac_key
    global tls_cert
    global tls_key
    global client_state
    global last_cred_update
    global last_service_refresh
    global services
    global last_access_refresh
    global access_list
    global conn_state
    global last_contact
    
    while(cnt < queue_len): # verifica come python accoda messaggi
        if(conn_state == "DISCONNECTED"):
            ssl_sock = client_connect(curr_sock, server_info)
        
        # if data received, get the header with following expected data length
        try:
            data_len_netw = curr_sock.recv(4)
        except socket.timeout:
            print("No data to read right now")
            break
        if not data_len_netw:
            print("Connection is down")
            break
        data_len = int.from_bytes(data_len_netw, 'little')
        data_len = socket.ntohl(data_len)
        print("Received ctr data of size " + str(data_len))
        
        # verify if data is of expected size
        if(data_len > SDP_COM_MAX_MSG_BLOCK_LEN): 
            print("data length indicated in header exceeds allowed size")
            break
        
        # receive json data message
        try:
            r_msg = curr_sock.recv(data_len)
        except socket.timeout:
            print("No data to read right now")
            break
        if not r_msg:
            print("no incoming data")
            break
        
        # verify if size is coherent
        bytes = len(r_msg)
        if(bytes != data_len):
            print("received data is not of the expected size")
            break
        if(bytes < SDP_MSG_MIN_LEN):
            print("received data is too small")
            break
        
        cnt = cnt + 1
        
        # message process
        json_msg = json.loads(r_msg.decode('utf-8'))
        print("Received JSON is " + str(json_msg))
        msg_action = json_msg.get("action") # o u'sdp_ket...'

        # ** credential good received **
        if(msg_action == "credentials_good"):
            print("Credentials-good message received")
            controller_ready = 1

        # ** keep alive received **
        elif(msg_action == "keep_alive"):
            print("Keep-alive response received")
            last_contact = dt.datetime.now()
            client_state = "ready"

        # ** credential update received **
        elif(msg_action == "credential_update"):
            print("Received credential update message")
            encryption_key = json_msg["data"]["spa_encryption_key_base64"]
            hmac_key = json_msg["data"]["spa_hmac_key_base64"]
            tls_cert = json_msg["data"]["tls_cert"]
            tls_key = json_msg["data"]["tls_key"]
            controller_ready = 1

            # Backup old credentials
            shutil.copy(certfile, os.path.join(os.sys.path[0], "Certs/backup/2.crt"))
            shutil.copy(keyfile, os.path.join(os.sys.path[0], "Certs/backup/2.key"))
            
            # Save new credentials
            f = open(certfile,'w')
            try:
                f.write(tls_cert)
            finally:
                f.close()
                
            f = open(keyfile,'w')
            try:
                f.write(tls_key)
            finally:
                f.close()
                
            client_state = "ready"
            
            last_cred_update = dt.datetime.now()
            
            send_message(curr_sock, 'credential_update_ack', None)

        # ** service refresh received **
        elif(msg_action == "service_refresh"):
            r_data = json_msg.get("data")
            print("Service data refresh received")
            last_service_refresh = dt.datetime.now()
            
            # delete current services instance and add the new ones
            services.clear()
            for i in r_data:
                curr_s_id = int(i.get('service_id'))
                curr_proto = i.get('proto')
                curr_port = i.get('port')
                curr_nat_ip = i.get('nat_ip')
                curr_nat_port = i.get('nat_port')
                services.append(service(curr_s_id, curr_proto, curr_port, curr_nat_ip, curr_nat_port))
                print("Added service entry for Service ID " + str(services[len(services)-1].service_id))
            
            send_message(curr_sock, 'service_ack', None)

        # ** service update received **
        elif(msg_action == "service_update"):
            r_data = json_msg.get("data")
            print("Service data update received")
            
            # add updated services
            for i in r_data:
                curr_s_id = int(i.get('service_id'))
    
                # delete oldest instance of service, if any
                for s in services:
                    if(s.service_id == curr_s_id):
                        services.remove(s)

                curr_proto = i.get('proto')
                curr_port = i.get('port')
                curr_nat_ip = i.get('nat_ip')
                curr_nat_port = i.get('nat_port')
                services.append(service(curr_s_id, curr_proto, curr_port, curr_nat_ip, curr_nat_port))
                print("Added service entry for Service ID " + str(services[len(services-1)].service_id))
            
            send_message(curr_sock, 'service_ack', None)
                        
        # ** service remove received **
        elif(msg_action == "service_remove"):
            r_data = json_msg.get("data")
            print("Service data remove received")
            for i in r_data:
                curr_s_id = int(i.get('service_id'))
    
                # delete instance of service, if any
                for s in services:
                    if(s.service_id == curr_s_id):
                        services.remove(s)

                print("Removed service entry for Service ID " + str(curr_s_id))
            
            send_message(curr_sock, 'service_ack', None)

        # ** access refresh received **
        elif(msg_action == "access_refresh"):
            r_data = json_msg.get("data")
            print("Access data refresh received")
            last_access_refresh = dt.datetime.now()
            
            # delete current access_list instance and add the new access
            access_list.clear()
            for i in r_data:
                curr_sdp_id = int(i.get('sdp_id'))
                curr_s_list = i.get('service_list')
                curr_ports = i.get('open_ports')
                curr_enc_key = i.get('spa_encryption_key_base64')
                curr_hmac_key = i.get('spa_hmac_key_base64')
                access_list.append(access(curr_sdp_id, curr_s_list, curr_ports, curr_enc_key, curr_hmac_key))
                print("Added access entry for SDP ID " + str(access_list[len(access_list)-1].sdp_id) + " to the service/s " + str(access_list[len(access_list)-1].service_list) + " w.r.t. this/these port/s " + str(access_list[len(access_list)-1].open_ports))
            
            send_message(curr_sock, 'access_ack', None)

        # ** access update received **
        elif(msg_action == "access_update"):
            r_data = json_msg.get("data")
            print("Access data update received")
            
            # add updated access
            for i in r_data:
                curr_sdp_id = int(i.get('sdp_id'))
                
                # delete oldest instance of same access, if one exists
                for a in access_list:
                    if(a.sdp_id == curr_sdp_id):
                        access_list.remove(a)
                
                curr_s_list = i.get('service_list')
                curr_ports = i.get('open_ports')
                curr_enc_key = i.get('spa_encryption_key_base64')
                curr_hmac_key = i.get('spa_hmac_key_base64')
                access_list.append(access(curr_sdp_id, curr_s_list, curr_ports, curr_enc_key, curr_hmac_key))
                print("Added access entry for SDP ID " + str(access_list[len(access_list)-1].sdp_id) + " to the service/s " + str(access_list[len(access_list)-1].service_list) + " w.r.t. this/these port/s " + str(access_list[len(access_list)-1].open_ports))
                    
            send_message(curr_sock, 'access_ack', None)

        # ** access remove received **
        elif(msg_action == "access_remove"):
            r_data = json_msg.get("data")
            print("Access data remove received")
            for i in r_data:
                curr_sdp_id = int(i.get('sdp_id'))
    
                # delete instance of access, if any
                for a in access_list:
                    if(a.sdp_id == curr_sdp_id):
                        access_list.remove(a)

                print("Removed access entry for Service ID " + str(curr_sdp_id))
            
            send_message(curr_sock, 'access_ack', None)

        # ** bad message alert received
        elif(msg_action == "bad_message"):
            r_data = json_msg.get("data")
            print("Received notice from controller that it received the following bad message:")
            print(r_data)

        else:
            print("Unknown message processing result")

def client_connect(sd, server_info):
    
    global conn_state
    # socket connect
    sd.connect(server_info[0][4])
    
    # SSL SSL_connect (sdp_com.c)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context.load_verify_locations(ca_file)
    ssl_context.load_cert_chain(certfile, keyfile)
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_sock = ssl_context.wrap_socket(sd, False, False, True, None, None)
    ssl_sock.settimeout(1)

    # Handshake
    ssl_sock.do_handshake()
    print(ssl_sock.getpeercert(False))
    print("Connected with " + str(ssl_sock.cipher()) + " encryption")
    
    conn_state = "CONNECTED"
    
    return ssl_sock

def sdp_thread_function(ssl_sock, server_info, msg_cnt):
    print("SDP gateway thread started")
    while(True):
        check_inbox(msg_cnt, 1, ssl_sock, server_info)
        # TODO if client_status = ready
        cred_update_req(ssl_sock, server_info, msg_cnt)
        serv_refresh_req(ssl_sock, server_info, msg_cnt)
        access_refresh_req(ssl_sock, server_info, msg_cnt)
        keep_alive_req(ssl_sock, server_info, msg_cnt)
        print("SDP thread still working")


# ___*** MAIN FUNCTION ***___

def main():


    # ** gateway switch definition
    sh.setup(
        device_id=0,
        grpc_addr='127.0.0.1:50051',
        election_id=(0, 1), # (high, low)
        config=sh.FwdPipeConfig('/home/switchp4/Desktop/TEST/build/p4info.txt', '/home/switchp4/Desktop/TEST/build/switch.json')
    )

    print("P4 Switch connected and configured")
    
    
    # ** setting table rules
    
    print("Writing switch startup table rules")
    
    writeFirewallRules(egress_port="0", dst_eth_addr="08:00:27:c1:60:c1", dst_ip_addr="192.168.1.11")
    
    writeFirewallRules(egress_port="1", dst_eth_addr="08:00:27:cc:9a:c9", dst_ip_addr="192.168.2.22")
    
    writeFirewallRules(egress_port="1", dst_eth_addr="08:00:27:cc:9a:c9", dst_ip_addr="192.168.4.44")
    
    writeFirewallRules(egress_port="2", dst_eth_addr="08:00:27:88:f8:9b", dst_ip_addr="192.168.3.33")


    # ** setting socket to controller
    
    print("Starting SSL socket")

    true = struct.pack('l', 1)
    ai_family   = socket.AF_UNSPEC
    ai_socktype = socket.SOCK_STREAM
    ai_protocol = socket.IPPROTO_TCP
    
    # TODO i seguenti param andrebbero letti da config file
    contr_ip = '192.168.3.33'
    contr_port = 5000
    conn_state = "DISCONNECTED"
    
    msg_cnt = 0
    message_queue_len = 10
    
    if(conn_state == "DISCONNECTED"):
        server_info = socket.getaddrinfo(contr_ip, contr_port, ai_family, ai_socktype, ai_protocol)
        sd =  socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0)
        sd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, true)
        ssl_sock = client_connect(sd, server_info)
    
    
    # ** start up gateway functions and lisening thread

    check_inbox(msg_cnt, 1, ssl_sock, server_info)
    
    cred_update_req(ssl_sock, server_info, msg_cnt)
    
    serv_refresh_req(ssl_sock, server_info, msg_cnt)
    
    access_refresh_req(ssl_sock, server_info, msg_cnt)
    
    x = threading.Thread(target = sdp_thread_function, args=(ssl_sock,server_info,msg_cnt))
    x.start()
    
    
    # ** listen for SPA messages
    
    connection = sh.client        
    while True:
        print("[SPA] Listening for SPA message")
        curr_packet = connection.stream_in_q.get()
        print("[SPA] Incoming UDP packet! Is SPA? Let's parse it" + str(curr_packet))
        print(type(curr_packet))
        
        # extract payload
        curr_payload = curr_packet.packet.payload
        print(len(curr_payload))
        print(curr_payload)
        ip_payload = curr_payload[12:]
        spa_payload = curr_payload[32:]
        
        # extract IP header
        print(spa_payload)
        curr_ip = IP(ip_payload)
        curr_ip.show()
        src = curr_ip[IP].src
        dst = curr_ip[IP].dst
        
        print("Received UDP packet from IP: " + str(src) + " to IP " + str(dst))
        
        parse_spa_packet(spa_payload, src, dst)
        
        # TODO Imposta firewall rules

if __name__ == "__main__":
    main()
