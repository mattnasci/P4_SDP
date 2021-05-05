import socket
import ssl
import math
import struct
import os
import json
import shutil
import datetime
import threading

SDP_COM_MAX_MSG_BLOCK_LEN = 16384
SDP_MSG_MIN_LEN = 22
CRED_UPDATE_INTERVAL = 7200
SERVICE_REFRESH_INTERVAL = 86400
ACCESS_REFRESH_INTERVAL = 86400
DEFAULT_INTERVAL_KEEP_ALIVE_SECONDS =10

ca_file = os.path.join(os.sys.path[0], "Certs/ca.crt")
certfile = os.path.join(os.sys.path[0], "Certs/2.crt")
keyfile = os.path.join(os.sys.path[0], "Certs/2.key")
controller_ready = 0
last_cred_update = datetime.datetime(1967, 1, 1)
last_service_refresh = datetime.datetime(1967, 1, 1)
last_access_refresh = datetime.datetime(1967, 1, 1)
last_contact = datetime.datetime(1967, 1, 1)
client_state = "ready"
services = []
access_list = []

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

def _seconds_to_second_microsecond_struct(seconds):
    microseconds_per_second = 1000000
    whole_seconds = math.floor(seconds)
    whole_microseconds = math.floor((seconds % 1) * microseconds_per_second)
    return struct.pack('ll', whole_seconds, whole_microseconds)
    
# def process_access_msg():

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
    if (datetime.datetime.now() >= last_cred_update + datetime.timedelta(seconds=CRED_UPDATE_INTERVAL)):
        print("It is time for a credential update request.")
        send_message(curr_sock,'credential_update_request',None)
        client_state = "cred_update"
        check_inbox(msg_cnt, 1, curr_sock, server_info)
        
def serv_refresh_req(curr_sock, server_info, msg_cnt):
    if (datetime.datetime.now() >= last_service_refresh + datetime.timedelta(seconds=SERVICE_REFRESH_INTERVAL)):
        print("It is time for a service refresh request.")
        send_message(curr_sock,'service_refresh_request',None)
        client_state = "service_update"
        check_inbox(msg_cnt, 1, curr_sock, server_info)
        
def access_refresh_req(curr_sock, server_info, msg_cnt):
    if (datetime.datetime.now() >= last_access_refresh + datetime.timedelta(seconds=ACCESS_REFRESH_INTERVAL)):
        print("It is time for aa access refresh request.")
        send_message(curr_sock,'access_refresh_request',None)
        client_state = "access_update"
        check_inbox(msg_cnt, 1, curr_sock, server_info)
        
def keep_alive_req(curr_sock, server_info, msg_cnt):
    if (datetime.datetime.now() >= last_contact + datetime.timedelta(seconds=DEFAULT_INTERVAL_KEEP_ALIVE_SECONDS)):
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
            #conn_state = "DISCONNECTED"
            #curr_sock.close()
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
        
        # TODO può essere che dobbiamo continuare a leggere? non credo
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
            last_contact = datetime.datetime.now()
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
            # TODO devo copiare spa? non credo
            
            last_cred_update = datetime.datetime.now()
            
            send_message(curr_sock, 'credential_update_ack', None)

        # ** service refresh received **
        elif(msg_action == "service_refresh"):
            r_data = json_msg.get("data")
            print("Service data refresh received")
            last_service_refresh = datetime.datetime.now()
            
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
            last_access_refresh = datetime.datetime.now()
            
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

def main():
    # true = Struct('i')
    # struct sockaddr_in addr
    true = struct.pack('l', 1)
    ai_family   = socket.AF_UNSPEC
    ai_socktype = socket.SOCK_STREAM
    ai_protocol = socket.IPPROTO_TCP
    
    # i seguenti param andrebbero letti da config file
    read_timeout = _seconds_to_second_microsecond_struct(1) 
    write_timeout = _seconds_to_second_microsecond_struct(1)
    contr_ip = '192.168.3.33'
    contr_port = 5000
    conn_state = "DISCONNECTED"
                    
    msg_cnt = 0
    message_queue_len = 10
    
    if(conn_state == "DISCONNECTED"):
        server_info = socket.getaddrinfo(contr_ip, contr_port, ai_family, ai_socktype, ai_protocol)
        sd =  socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0)
        sd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, true)
        # sd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, read_timeout)
        # sd.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, write_timeout)
        ssl_sock = client_connect(sd, server_info)
        
    check_inbox(msg_cnt, 1, ssl_sock, server_info)
    
    cred_update_req(ssl_sock, server_info, msg_cnt)
    
    serv_refresh_req(ssl_sock, server_info, msg_cnt)
    
    access_refresh_req(ssl_sock, server_info, msg_cnt)
    
    x = threading.Thread(target = sdp_thread_function, args=(ssl_sock,server_info,msg_cnt))
    x.start()

if __name__ == "__main__":
    main()
