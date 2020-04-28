from enum import IntEnum, unique
import time
from time import sleep
from helper_functions import *
from Fake_SMS_handler import Fake_SMS_handler
from Airmore_SMS_handler import Airmore_SMS_handler
from statistics import mean
import sys

# See README for protocol explanation

HEADER_PROTOCOL_TYPE = pack_bytes([(42,1)]) # SecureSMS
HEADER_VERSION = b'00'
MAX_MESSAGE_LENGTH = 121
HEADER_SIZE = 5

@unique
class Message_type(IntEnum):
    ALICE_PUBLIC_KEY_1 = 0
    ALICE_PUBLIC_KEY_2 = 1
    ALICE_PUBLIC_KEY_3 = 2
    ALICE_PUBLIC_KEY_4 = 3
    BOB_GA_PUBLIC_KEY_1 = 4
    BOB_GA_PUBLIC_KEY_2 = 5
    BOB_GA_PUBLIC_KEY_3 = 6
    BOB_GA_PUBLIC_KEY_4 = 7
    ALICE_GB_1 = 8
    ALICE_GB_2 = 9
    DATA = 10

class Secure_SMS_socket_like_interface(object):
    def __init__(self, sms_handler):
        self.__handler = sms_handler
        self.__buffer = b''
    
    def sendall(self, data):
        assert isinstance(data, bytes)
        self.__handler.send(convert_bytes_to_ascii_bytes(data).decode())
    
    def recv(self, length):
        if length > len(self.__buffer):
            for message in self.__handler.get_new_messages():
                self.__buffer += convert_ascii_bytes_to_bytes(message.encode())
        ret_val = self.__buffer[:min(len(self.__buffer), length)]
        self.__buffer = self.__buffer[min(len(self.__buffer), length):]
        return ret_val
        

class Secure_SMS(object):
    def __init__(self, sms_handler, certifier_pub_key):
        self.__sms_handler = sms_handler
        self.__local_public_key, self.__local_private_key = generate_RSA_public_private_pair()
        self.__certifier_pub_key = certifier_pub_key
        self.__signed_local_pub_key_bytes = None
        self.__remote_public_key = None
        self.__network_public_key = None # TODO
        self.__local_dh_pub_key, self.__shared_secret_generator = diffie_hellman()
        self.__handshake_messages = [None for _ in range(Message_type.DATA)]
        self.__AES_encrypt = None
        self.__AES_decrypt = None

    def sign_public_key(self, certifier_priv_key):
        self.__signed_local_pub_key_bytes = RSA_sign(public_key_to_bytes(self.__local_public_key), certifier_priv_key)

    def alice_send_public_key(self):
        pub_key_bytes = self.__signed_local_pub_key_bytes

        message_types = [Message_type.ALICE_PUBLIC_KEY_1, 
                    Message_type.ALICE_PUBLIC_KEY_2, 
                    Message_type.ALICE_PUBLIC_KEY_3, 
                    Message_type.ALICE_PUBLIC_KEY_4]
        
        for i, msg_type in enumerate(message_types):
            msg_size = len(pub_key_bytes)//len(message_types)
            part = pub_key_bytes[i*msg_size:(i+1)*msg_size]
            msg = pack_bytes([Secure_SMS.create_header(msg_type, len(part)), part])
            self.__sms_handler.sendall(msg)

        return pub_key_bytes
    
    def bob_receive_alice_public_key(self):
        for _ in range(4):
            header = recvall(self.__sms_handler, HEADER_SIZE)
            msg_type, length = Secure_SMS.unpack_header(header)
            self.__handshake_messages[msg_type] = recvall(self.__sms_handler, length)

        assert self.__handshake_messages[Message_type.ALICE_PUBLIC_KEY_1] != None
        assert self.__handshake_messages[Message_type.ALICE_PUBLIC_KEY_2] != None
        assert self.__handshake_messages[Message_type.ALICE_PUBLIC_KEY_3] != None
        assert self.__handshake_messages[Message_type.ALICE_PUBLIC_KEY_4] != None
        data_bytes = pack_bytes(self.__handshake_messages[Message_type.ALICE_PUBLIC_KEY_1:Message_type.ALICE_PUBLIC_KEY_4+1])

        self.__remote_public_key = bytes_to_public_key(RSA_verify(data_bytes, self.__certifier_pub_key))

        return data_bytes

    def bob_send_dh_val_and_public_key(self):
        diffie_hellman_bytes = diffie_hellman_public_key_to_bytes(self.__local_dh_pub_key)
        encrypted_value = RSA_encrypt(diffie_hellman_bytes, self.__remote_public_key)
        data_bytes = encrypted_value + self.__signed_local_pub_key_bytes

        message_types = [Message_type.BOB_GA_PUBLIC_KEY_1, 
                         Message_type.BOB_GA_PUBLIC_KEY_2, 
                         Message_type.BOB_GA_PUBLIC_KEY_3, 
                         Message_type.BOB_GA_PUBLIC_KEY_4]
        
        for i, msg_type in enumerate(message_types):
            msg_size = len(data_bytes)//len(message_types)
            part = data_bytes[i*msg_size:(i+1)*msg_size]
            msg = pack_bytes([Secure_SMS.create_header(msg_type, len(part)), part])
            self.__sms_handler.sendall(msg)

        return data_bytes

    def alice_receive_dh_val_and_bob_public_key(self):
        for _ in range(4):
            header = recvall(self.__sms_handler, HEADER_SIZE)
            msg_type, length = Secure_SMS.unpack_header(header)
            self.__handshake_messages[msg_type] = recvall(self.__sms_handler, length)

        assert self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_1] != None
        assert self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_2] != None
        assert self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_3] != None
        assert self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_4] != None
        data_bytes = pack_bytes(self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_1:Message_type.BOB_GA_PUBLIC_KEY_4+1])
        
        encrypted_value_length = 128
        self.__remote_diffie_hellman_val = RSA_decrypt(data_bytes[:encrypted_value_length], self.__local_private_key)
        self.__remote_public_key = bytes_to_public_key(data_bytes[encrypted_value_length:])

        return data_bytes

    def alice_send_dh_val(self):
        diffie_hellman_bytes = diffie_hellman_public_key_to_bytes(self.__local_dh_pub_key)
        data_bytes = RSA_encrypt(diffie_hellman_bytes, self.__remote_public_key)
        part1 = data_bytes[:len(data_bytes)//2]
        part2 = data_bytes[len(data_bytes)//2:]

        message_types = [Message_type.ALICE_GB_1, 
                         Message_type.ALICE_GB_2]
        
        for i, msg_type in enumerate(message_types):
            msg_size = len(data_bytes)//len(message_types)
            part = data_bytes[i*msg_size:(i+1)*msg_size]
            msg = pack_bytes([Secure_SMS.create_header(msg_type, len(part)), part])
            self.__sms_handler.sendall(msg)

        return data_bytes

    def bob_receive_dh_val(self):
        for _ in range(2):
            header = recvall(self.__sms_handler, HEADER_SIZE)
            msg_type, length = Secure_SMS.unpack_header(header)
            self.__handshake_messages[msg_type] = recvall(self.__sms_handler, length)

        assert self.__handshake_messages[Message_type.ALICE_GB_1] != None
        assert self.__handshake_messages[Message_type.ALICE_GB_2] != None
        data_bytes = pack_bytes(self.__handshake_messages[Message_type.ALICE_GB_1:Message_type.ALICE_GB_2+1])

        self.__remote_diffie_hellman_val = RSA_decrypt(data_bytes, self.__local_private_key)
        return data_bytes

    def generate_shared_secret(self):
        diffie_hellman_pub_key = bytes_to_diffie_hellman_public_key(self.__remote_diffie_hellman_val)
        shared_secret = self.__shared_secret_generator(diffie_hellman_pub_key)
        self.__AES_encrypt, self.__AES_decrypt = AES_CBC(shared_secret[:32], shared_secret[32:])
        return shared_secret

    def send_message(self, message):
        message_bytes = message.encode()
        encrypted = self.__AES_encrypt(message_bytes + bytes(0x00 for padding in range(16-len(message_bytes)%16)))
        packed = pack_bytes([Secure_SMS.create_header(Message_type.DATA, len(encrypted)), encrypted])
        self.__sms_handler.sendall(packed)

    def receive_message(self):
        header = recvall(self.__sms_handler, HEADER_SIZE)
        msg_type, length = Secure_SMS.unpack_header(header)
        assert msg_type == Message_type.DATA
        encrypted = recvall(self.__sms_handler, length)
        #Decrypt, decode, and remove padding
        return self.__AES_decrypt(encrypted).decode().rstrip('\x00')

    def clear_buffer(self):
        self.__sms_handler.recv(sys.maxsize)

    @staticmethod
    def create_header(message_type, data_length):
        assert isinstance(message_type, Message_type)
        assert isinstance(data_length, int)
        assert data_length <= MAX_MESSAGE_LENGTH
        return pack_bytes([(HEADER_PROTOCOL_TYPE, 1), HEADER_VERSION, (message_type, 1), (data_length, 1)])

    @staticmethod
    def unpack_header(header):
        assert isinstance(header, bytes)
        assert len(header) == HEADER_SIZE, f'Length was {len(header)} instead of {HEADER_SIZE}'
        byte_list = [header[i:i+1] for i in range(len(header))]
        assert byte_list[0] == HEADER_PROTOCOL_TYPE
        assert byte_list[1]+byte_list[2] == HEADER_VERSION
        int_list = bytes_to_ints([byte_list[3], byte_list[4]])
        return int_list 

def run_handshake():
    #handler1, handler2 = Fake_SMS_handler.create_fake_connection()
    handler1, handler2 = Airmore_SMS_handler.create_test_connection()
    certifier_pub, certifier_priv = generate_RSA_public_private_pair()
    handler1, handler2 = Secure_SMS_socket_like_interface(handler1), Secure_SMS_socket_like_interface(handler2)
    alice = Secure_SMS(handler1, certifier_pub)
    bob = Secure_SMS(handler2, certifier_pub)

    alice.sign_public_key(certifier_priv)
    bob.sign_public_key(certifier_priv)
    
    sent = alice.alice_send_public_key()
    print(f'Alice sent public key -- {sent}')
    received = bob.bob_receive_alice_public_key()
    print(f'Bob received public key -- {received}')
    assert sent == received

    sent = bob.bob_send_dh_val_and_public_key()
    print(f'Bob sent diffie helman value and public key -- {sent}')
    received = alice.alice_receive_dh_val_and_bob_public_key()
    print(f'Alice received diffie helman value and public key -- {received}')
    assert sent == received

    sent = alice.alice_send_dh_val()
    print(f'Alice sent diffie helman value -- {sent}')
    received = bob.bob_receive_dh_val()
    print(f'Alice received diffie helman value -- {received}')
    assert sent == received

    alice_shared_secret = alice.generate_shared_secret()
    print(f'Alice generated session key -- {alice_shared_secret}')
    bob_shared_secret = bob.generate_shared_secret()
    print(f'Bob generated session key -- {bob_shared_secret}')
    print()
    assert alice_shared_secret == bob_shared_secret

    return alice, bob

if __name__ == '__main__':
    failed_handshakes = 0
    total_time = 0
    number_of_trials = 200
    handshake_times = []
    time_of_day = []
    for _ in range(number_of_trials):
        try:
            start = time.time()
            time_of_day.append(start)
            alice, bob = run_handshake()
            handshake_times.append(time.time() - start)
        except:
            failed_handshakes += 1
            handshake_times.append(None)
            # If failed, give some time for messages to finish sending...
            print('Allow late messages to come through...')
            sleep(60)

    print()
    print(f'Number of Handshakes = {number_of_trials}')
    print(f'Failed_handshakes = {failed_handshakes}')
    print(f'Average Handshake Time = {mean([val for val in handshake_times if val != None])} seconds')

    print()
    print('Handshake Times')
    print(handshake_times)
    print('Time of Day')
    print(time_of_day)
    print()

    if failed_handshakes != 0:
        sleep(60)
    bob.clear_buffer()

    dropped_or_late_data_packets = 0
    message = 'Test Message'
    data_latencies = []
    time_of_day = []
    for i in range(5*number_of_trials):
        try:
            start = time.time()
            time_of_day.append(start)
            alice.send_message(message)
            received = bob.receive_message()
            data_latencies.append(time.time() - start)
        except:
            dropped_or_late_data_packets += 1
            data_latencies.append(None)
    
    print(f'Number of Data Packets = {5*number_of_trials}')
    print(f'Dropped_or_late_data_packets = {dropped_or_late_data_packets}')
    print(f'Average latency = {mean([val for val in data_latencies if val != None])}')
    print()
    print('Data Latencies')
    print(data_latencies)
    print('Time of Day')
    print(time_of_day)
    print()
