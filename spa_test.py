# SPA PACKET PARSER TEST
# Python 3

import json
import base64
import binascii
import hmac

# from Crypto.Protocol.KDF import PBKDF1
# from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
# from hashlib import md5

from scapy.all import *
from hashlib import sha256

services=[]
access_list=[]
digest_list=[]

MIN_SPA_DATA_SIZE = 80
MAX_SPA_PACKET_LEN = 1500
B64_RIJNDAEL_SALT = "U2FsdGVkX1"
B64_RIJNDAEL_SALT_STR_LEN = 10
FKO_SDP_ID_SIZE = 4
SHA256_B64_LEN = 43
RIJNDAEL_BLOCKSIZE = 16

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

# TODO class spa_pkt_info:

def parse_service_json():
    # extracting JSON for gateway service
    with open("services.json", "r") as sj:
        s_json = json.load(sj)
        print("Loaded this new service json: ")
        print(s_json)
        curr_s_id = int(s_json.get(u'service_id'))
        curr_proto = s_json.get(u'proto')
        curr_port = s_json.get(u'port')
        curr_nat_ip = s_json.get(u'nat_ip')
        curr_nat_port = s_json.get(u'nat_port')
        services.append(service(curr_s_id, curr_proto, curr_port, curr_nat_ip, curr_nat_port))
        print("added service id " + str(services[0].service_id) + " to the services list")

def parse_access_json():
    # TODO parse JSON with multiple entries
    # extracting JSON for authorized users
    
    with open("access_3.json", "r") as aj:
        a_json = json.load(aj)
        print("Loaded this new access json: ")
        print(a_json)
        curr_sdp_id = int(a_json.get(u'sdp_id'))
        curr_s_list = a_json.get(u'service_list')
        print(curr_s_list)
        curr_ports = a_json.get(u'open_ports')
        curr_enc_key = a_json.get(u'spa_encryption_key_base64')
        curr_hmac_key = a_json.get(u'spa_hmac_key_base64')
        access_list.append(access(curr_sdp_id, curr_s_list, curr_ports, curr_enc_key, curr_hmac_key))
        print("added access for sdp id " + str(access_list[0].sdp_id) + " to the service/s " + str(access_list[0].service_list) + " w.r.t. this/these port/s " + str(access_list[0].open_ports))

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
    
        # print((buf[i:i+1]))
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


def parse_spa_packet(spa_message, source, destination):
    # TODO extract ip s/d, port d/d, data parmeters from spa_message
    spa_obj = spa_packet(spa_message)
    spa_obj.packet_proto = "UDP"
    spa_obj.packet_src_ip = source
    spa_obj.packet_dst_ip = destination

    if spa_obj.packet_data_len > MAX_SPA_PACKET_LEN:
        print("packet exceed max SPA")
        return # TODO not spa message

    if spa_obj.packet_data_len < MIN_SPA_DATA_SIZE:
        print("packet too small")
        return # TODO not spa message
        
    print("SPA message is of the right size")

    # verify no rijndael prefix
    if constant_runtime_cmp(spa_obj.packet_data, B64_RIJNDAEL_SALT, B64_RIJNDAEL_SALT_STR_LEN) == 0:
        print("packet is forged")
        return # SPA_MSG_BAD_DATA
        
    print("SPA message has no forged prefix")

    # verify if base64 encoding
    if not is_base64(spa_obj.packet_data, spa_obj.packet_data_len):
        print("packet has invalid characters")
        return #SPA_MSG_NOT_SPA_DATA
        
    print("SPA message is base64")
    
    # extract encoded sdp id
    encoded_sdp_id = spa_obj.packet_data[:6]
    print("Encoded SDP ID extracted " + encoded_sdp_id.decode())
    
    padd = (4 - len(encoded_sdp_id) % 4) % 4
    for i in range(padd):
        encoded_sdp_id = bytearray(encoded_sdp_id)
        encoded_sdp_id.extend('='.encode('latin-1'))
    print("Encoded SDP ID padded " + encoded_sdp_id.decode())
    
    # decode from b64 to original data
    decoded_sdp_id = (base64.b64decode(encoded_sdp_id))
    # TODO SDP ID, ora stringa, farlo diventare int
    print("Decoded SDP ID is: " + decoded_sdp_id.decode())
    print(type(decoded_sdp_id))
    
    spa_obj.sdp_id = int.from_bytes(decoded_sdp_id, "little")
    print("SDP ID inserted in spaobj as: " + str(spa_obj.sdp_id))
    print(type(spa_obj.sdp_id))

    if (spa_obj.sdp_id == 0):
        return # SPA_MSG_BAD_DATA
    
    # TODO make a string version too
    # in C is : sn# printf(spa_pkt->sdp_id_str, MAX_SDP_ID_STR_LEN, "%"PRIu32, sdp_id);
    
    #replay check: fai SHA256 converti in base64, compara con archivio digest e salva
    m = hashlib.sha256()
    m.update(spa_obj.packet_data)
    curr_digest = base64.b64encode(m.digest())
    print("SPA messgage B64 digested is: " + str(curr_digest))
    for i in digest_list:
        if i == curr_digest:
            print("FOUND SAME DIGEST, REPLAY ATTACK!")
            return #REPLAY_ATTACK_ERR
    digest_list.append(curr_digest)
    print("Digest saved, current archive is:")
    print(digest_list)

    #SDP ID check
    for a in access_list:
        if a.sdp_id == spa_obj.sdp_id:
            print("Match found for the SDP ID in access database")
            curr_stanza = a
        else:
            print("Not an authorized SDP ID")
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

    print("Extracted HMAC is")
    print(hmac_digest)
    print("Calculated HMAC is")
    print(curr_digest)

    if (constant_runtime_cmp(hmac_digest, curr_digest, len(hmac_digest)) != 0):
        print("HMAC verification failed")
        return # INVALID_DATA_HMAC_COMPAREFAIL

    # ** HMAC verified, remove SDP_ID from message and HMAC
    # message_b64 = spa_obj.packet_data[6:]
    message_b64 = bytes(B64_RIJNDAEL_SALT, 'latin-1') + spa_obj.packet_data[6:-SHA256_B64_LEN]
    message_b64 = add_padding(message_b64)
    message_len_b64 = len(message_b64)
    spa_obj.message_data = base64.b64decode(message_b64)
    spa_obj.message_data_len = len(spa_obj.message_data)

    # ** Message decryption
    if((spa_obj.message_data_len % RIJNDAEL_BLOCKSIZE) != 0):
        print("wrong cipher size!")
        return

    salt = spa_obj.message_data[8:16]
    ciphertext = spa_obj.message_data[16:]
    
    password = base64.b64decode(curr_stanza.spa_encryption_key_base64)
    # pbkdf1Hash = PBKDF1(bytes(password), salt, 32 + 16, count=100000, hashAlgo=MD5)
    # key = pbkdf1Hash[0:32]
    # iv = pbkdf1Hash[32:32 + 16]

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
    print("SPA message is decrypted! Content is: " + str(decrypted))
    
    # TODO check su parametri dati
    # decrypted dev'essere di dimensione > len(cipher) - 32
    # Make sure there are no non-ascii printable chars
    # Make sure there are enough fields in the SPA packet delimited with ':' chars
    
    # ** Parsing
    field_parser=[]
    
    #field_parser[0]    = parse_rand_val;       #* Extract random value */
    #field_parser[1]    = parse_timestamp;      #* Client timestamp */
    #field_parser[2]    = parse_msg_type;       #* SPA msg type */
    #field_parser[3]    = parse_msg;            #* SPA msg string */
    #field_parser[4]    = parse_nat_msg;        #* SPA NAT msg string */
    #field_parser[5]    = parse_server_auth;    #* optional server authentication method */
    
    fields = decrypted.split(b':')
    digest = fields.pop()
    tbuf = decrypted[:-(len(digest)+1)]
    
    # verify digest
    s = hashlib.sha256()
    s.update(tbuf)
    curr_digest = base64.b64encode(s.digest())
    print(curr_digest)
    digest_pad = add_padding(digest)
    print(digest_pad)
    if (constant_runtime_cmp(digest_pad, curr_digest, len(digest_pad)) != 0):
        print("Digest verification failed")
        return # DIGEST_VERIFICATION_FAILED
        
    # message
    msg = base64.b64decode(add_padding(fields[3]))
    msg = msg.split(b',')
    spa_ip = msg[0]
    service_req = []
    allowed_serv = []
    for s in range(1, len(msg)):
        service_req.append(msg[s])
    print("receive SPA message from IP " + str(spa_ip) + " for services " + str(service_req))
    
    # TODO Verifica TimeOut check_pkt_age in incoming_spa
    
    for a in access_list:
        if a.sdp_id == spa_obj.sdp_id:
            a_services = a.service_list.split(", ")
            for s in a_services:
                for r in service_req:
                    r = r.decode("utf-8")
                    if s == r:
                        allowed_serv.append(r)
        else:
            print("Not an authorized SDP ID")
            return #SPA_FROM_UNAUTH_SDPID
            
    print("SDP ID " + str(spa_obj.sdp_id) + " is allowed to access service/s: " + str(allowed_serv))
    
    
def main():
    print("main execution")
    parse_service_json()
    parse_access_json()
    # SPA packet load and analysis
    packet = rdpcap('SPA_PACKET.pcap')
    print(packet)
    for p in packet:
        if(p.haslayer(UDP) == 1):
            payload = p[UDP].payload.load
            print(type(payload))
            print(payload)
            src = p[IP].src
            dst = p[IP].dst
            print("Received UDP packet from IP: " + str(src) + " to IP " + str(dst))
            parse_spa_packet(payload, src, dst)
#            curr_spa = parse_spa_packet(payload)
#            print("Received correct SPA packet with SDP ID " + str(curr_spa.sdp_id))

if __name__ == "__main__":
    main()
