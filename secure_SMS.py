from Twilio_SMS_handler import Twilio_SMS_handler
from enum import Enum, unique

# See README for protocol explanation

HEADER_PROTOCOL_TYPE = 42 # SecureSMS
HEADER_VERSION = b'00'
MAX_MESSAGE_LENGTH = 92

@unique
class Message_type(Enum):
    ALICE_PUBLIC_KEY_1 = 0
    ALICE_PUBLIC_KEY_2 = 1
    BOB_GA_PUBLIC_KEY_1 = 2
    BOB_GA_PUBLIC_KEY_2 = 3
    ALICE_GB = 4
    DATA = 5

class Secure_SMS(object):
    def __init__(self, sms_handler):
        self.__sms_handler = sms_handler
        self.__local_public_key = None # TODO
        self.__local_private_key = None # TODO
        self.__remote_public_key = None
        self.__network_public_key = None # TODO
        self.__local_diffie_hellman_val = None # TODO
        self.__remote_diffie_hellman_val = None
        self.__shared_secret = None
        self.__AES_encrypt = None
        self.__AES_decrypt = None

    def alice_send_public_key(self):
        # TODO
        pass
    
    def bob_receive_alice_public_key(self):
        # TODO
        pass

    def bob_send_dh_val_and_public_key(self):
        # TODO
        pass

    def alice_receive_dh_val_and_bob_public_key(self):
        # TODO
        pass

    def alice_send_dh_val(self):
        # TODO
        pass

    @staticmethod
    def create_header(message_type, data_length):
        assert isinstance(message_type, Message_type)
        assert isinstance(data_length, int)
        assert data_length <= MAX_MESSAGE_LENGTH
        return Secure_SMS.__pack_bytes([(HEADER_PROTOCOL_TYPE, 1), HEADER_VERSION, (data_length, 1)])

    @staticmethod
    def __pack_bytes(parts):
        ret_val = b''
        for part in parts:
            actual_part, num_bytes = part if isinstance(part, tuple) else (part, 1)
            assert isinstance(actual_part, int) or isinstance(actual_part, bytes)
            assert isinstance(num_bytes, int)
            if isinstance(actual_part, bytes):
                ret_val += actual_part
            else:
                ret_val += int.to_bytes(actual_part, num_bytes, 'big')
        return ret_val 




if __name__ == '__main__':
    print(Secure_SMS.create_header(Message_type.ALICE_PUBLIC_KEY_1, 92))
