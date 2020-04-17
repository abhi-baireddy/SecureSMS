import twilio_account_info
from twilio.rest import Client
from time import sleep
import datetime
import sys
import re
import pytz
import helper_functions
from helper_functions import recvall

# A Fake SMS handler to be used for testing
class Fake_SMS_handler(object):
    def __init__(self):
        self.__buffer = b''
        self.__remote = None

    def recv(self, length=sys.maxsize):
        ret_val = self.__buffer[0:min([length, len(self.__buffer)])]
        self.__buffer = self.__buffer[len(ret_val):]
        return ret_val

    def sendall(self, data):
        self.__remote.__add_to_buffer(helper_functions.convert_bytes_to_ascii_bytes(data))

    def __add_to_buffer(self, data):
        self.__buffer += helper_functions.convert_ascii_bytes_to_bytes(data)

    def __set_remote(self, remote):
        self.__remote = remote

    @staticmethod
    def create_fake_connection():
        handler1 = Fake_SMS_handler()
        handler2 = Fake_SMS_handler()
        handler1.__set_remote(handler2)
        handler2.__set_remote(handler1)
        return handler1, handler2

if __name__ == '__main__':
    handler1, handler2 = Fake_SMS_handler.create_fake_connection()
    
    handler1_send_bytes = b'To handler2 from handler1'
    handler2_send_bytes = b'To handler1 from handler2'
    handler1.sendall(handler1_send_bytes)
    handler2.sendall(handler2_send_bytes)

    assert recvall(handler2, len(handler1_send_bytes)) == handler1_send_bytes
    assert recvall(handler1, len(handler2_send_bytes)) == handler2_send_bytes
    print('Passed Test!')
