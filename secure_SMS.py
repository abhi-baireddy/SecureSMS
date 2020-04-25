from enum import IntEnum, unique
from time import sleep
from helper_functions import *
from Fake_SMS_handler import Fake_SMS_handler
from Airmore_SMS_handler import Airmore_SMS_handler

# See README for protocol explanation

#TODO improve diffie-hellman to generate larger shared secret
#TODO use shared secret as key for AES in data portion (use AES helper function in helper_functions)

HEADER_PROTOCOL_TYPE = pack_bytes([(42,1)]) # SecureSMS
HEADER_VERSION = b'00'
MAX_MESSAGE_LENGTH = 121
HEADER_SIZE = 5

def sleep_if_not_fake(handler):
    if not isinstance(handler, Fake_SMS_handler):
        pass#sleep(20)

@unique
class Message_type(IntEnum):
    ALICE_PUBLIC_KEY_1 = 0
    ALICE_PUBLIC_KEY_2 = 1
    BOB_GA_PUBLIC_KEY_1 = 2
    BOB_GA_PUBLIC_KEY_2 = 3
    BOB_GA_PUBLIC_KEY_3 = 4
    ALICE_GB_1 = 5
    ALICE_GB_2 = 6
    DATA = 7

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
    def __init__(self, sms_handler):
        self.__sms_handler = sms_handler
        self.__local_public_key, self.__local_private_key = generate_RSA_public_private_pair()
        self.__remote_public_key = None
        self.__network_public_key = None # TODO
        self.__local_dh_pub_key, self.__shared_secret_generator = diffie_hellman()
        self.__handshake_messages = [None for _ in range(Message_type.DATA)]
        self.__shared_secret = None
        self.__AES_encrypt = None
        self.__AES_decrypt = None

    def alice_send_public_key(self):
        pub_key_bytes = public_key_to_bytes(self.__local_public_key)
        first_half = pub_key_bytes[:len(pub_key_bytes)//2]
        second_half = pub_key_bytes[len(pub_key_bytes)//2:]
        msg1 = pack_bytes([Secure_SMS.create_header(Message_type.ALICE_PUBLIC_KEY_1, len(first_half)), first_half])
        msg2 = pack_bytes([Secure_SMS.create_header(Message_type.ALICE_PUBLIC_KEY_2, len(second_half)), second_half])

        self.__sms_handler.sendall(msg1)
        sleep_if_not_fake(self.__sms_handler)
        self.__sms_handler.sendall(msg2)
        return pub_key_bytes
    
    def bob_receive_alice_public_key(self):
        for _ in range(2):
            header = recvall(self.__sms_handler, HEADER_SIZE)
            msg_type, length = Secure_SMS.unpack_header(header)
            self.__handshake_messages[msg_type] = recvall(self.__sms_handler, length)

        assert self.__handshake_messages[Message_type.ALICE_PUBLIC_KEY_1] != None
        assert self.__handshake_messages[Message_type.ALICE_PUBLIC_KEY_2] != None
        data_bytes = pack_bytes(self.__handshake_messages[Message_type.ALICE_PUBLIC_KEY_1:Message_type.ALICE_PUBLIC_KEY_2+1])

        self.__remote_public_key = bytes_to_public_key(data_bytes)

        return data_bytes

    def bob_send_dh_val_and_public_key(self):
        diffie_hellman_bytes = diffie_hellman_public_key_to_bytes(self.__local_dh_pub_key)
        encrypted_value = RSA_encrypt(diffie_hellman_bytes, self.__remote_public_key)
        data_bytes = encrypted_value + public_key_to_bytes(self.__local_public_key)

        first_part = data_bytes[:len(data_bytes)//3]
        second_part = data_bytes[len(data_bytes)//3:2*len(data_bytes)//3]
        third_part = data_bytes[2*len(data_bytes)//3:]
        msg1 = pack_bytes([Secure_SMS.create_header(Message_type.BOB_GA_PUBLIC_KEY_1, len(first_part)), first_part])
        msg2 = pack_bytes([Secure_SMS.create_header(Message_type.BOB_GA_PUBLIC_KEY_2, len(second_part)), second_part])
        msg3 = pack_bytes([Secure_SMS.create_header(Message_type.BOB_GA_PUBLIC_KEY_3, len(third_part)), third_part])

        self.__sms_handler.sendall(msg1)
        sleep_if_not_fake(self.__sms_handler)
        self.__sms_handler.sendall(msg2)
        sleep_if_not_fake(self.__sms_handler)
        self.__sms_handler.sendall(msg3)
        return data_bytes

    def alice_receive_dh_val_and_bob_public_key(self):
        for _ in range(3):
            header = recvall(self.__sms_handler, HEADER_SIZE)
            msg_type, length = Secure_SMS.unpack_header(header)
            self.__handshake_messages[msg_type] = recvall(self.__sms_handler, length)

        assert self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_1] != None
        assert self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_2] != None
        assert self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_3] != None
        data_bytes = pack_bytes(self.__handshake_messages[Message_type.BOB_GA_PUBLIC_KEY_1:Message_type.BOB_GA_PUBLIC_KEY_3+1])
        
        encrypted_value_length = 128
        self.__remote_diffie_hellman_val = RSA_decrypt(data_bytes[:encrypted_value_length], self.__local_private_key)
        self.__remote_public_key = bytes_to_public_key(data_bytes[encrypted_value_length:])

        return data_bytes

    def alice_send_dh_val(self):
        diffie_hellman_bytes = diffie_hellman_public_key_to_bytes(self.__local_dh_pub_key)
        data_bytes = RSA_encrypt(diffie_hellman_bytes, self.__remote_public_key)
        part1 = data_bytes[:len(data_bytes)//2]
        part2 = data_bytes[len(data_bytes)//2:]
        
        msg1 = pack_bytes([Secure_SMS.create_header(Message_type.ALICE_GB_1, len(part1)), part1])
        msg2 = pack_bytes([Secure_SMS.create_header(Message_type.ALICE_GB_2, len(part2)), part2])
        self.__sms_handler.sendall(msg1)
        sleep_if_not_fake(self.__sms_handler)
        self.__sms_handler.sendall(msg2)
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
        self.__shared_secret = self.__shared_secret_generator(diffie_hellman_pub_key)[:32]
        self.__AES_encrypt, self.__AES_decrypt = AES_ECB(self.__shared_secret)
        return self.__shared_secret

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

if __name__ == '__main__':
    header = Secure_SMS.create_header(Message_type.ALICE_PUBLIC_KEY_1, 16)
    msg_type, length = Secure_SMS.unpack_header(header)
    assert msg_type == Message_type.ALICE_PUBLIC_KEY_1
    assert length == 16

    #handler1, handler2 = Fake_SMS_handler.create_fake_connection()
    handler1, handler2 = Airmore_SMS_handler.create_test_connection()

    handler1, handler2 = Secure_SMS_socket_like_interface(handler1), Secure_SMS_socket_like_interface(handler2)
    alice = Secure_SMS(handler1)
    bob = Secure_SMS(handler2)
    
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
    assert alice_shared_secret == bob_shared_secret

    message = 'Test message'
    alice.send_message(message)
    print(f'Alice sent message -- {message}')
    received = bob.receive_message()
    print(f'Bob received message -- {received}')

    assert message == received
    
    print('Passed tests!')
