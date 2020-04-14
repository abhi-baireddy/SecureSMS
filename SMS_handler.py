import twilio_account_info
from twilio.rest import Client
from time import sleep
import datetime
import sys
import re
import pytz
import base64

class SMS_handler(object):
    def __init__(self, account_info, send_number):
        self.__client = Client(account_info[0], account_info[1])
        self.__this_number = account_info[2]
        self.__send_number = send_number
        self.__buffer = b''
        self.__last_time_checked = pytz.UTC.localize(datetime.datetime.utcnow())
        self.__regex = re.compile(r'^Sent from your Twilio trial account - ')

    def sendall(self, data):
        self.__client.messages.create(
                     body=SMS_handler.convert_bytes_to_ascii_bytes(data),
                     from_=self.__this_number,
                     to=self.__send_number
                 )
    
    def recv(self, num_bytes=sys.maxsize):
        if len(self.__buffer) < num_bytes:
            current_time = pytz.UTC.localize(datetime.datetime.utcnow())
            messages = self.__client.messages.list(to=self.__this_number,
                                                   from_=self.__send_number,
                                                   date_sent_before=current_time,
                                                   date_sent_after=self.__last_time_checked)
            for message in messages:
                self.__buffer += SMS_handler.convert_ascii_bytes_to_bytes(self.__regex.sub('', message.body))
            self.__last_time_checked = current_time

        ret_val = self.__buffer[:min([num_bytes, len(self.__buffer)])]
        self.__buffer = self.__buffer[len(ret_val):]
        return ret_val

    @staticmethod
    def convert_bytes_to_ascii_bytes(data):
        '''
        SMS can only send ASCII bytes, so this will base85 encode all the
        bytes so they can be sent properly. This will unfortunately take
        up more space per message. yENC is another format that has more
        space efficiency, but we'd need to pull in another module for that.
        '''
        return base64.b85encode(data)

    @staticmethod
    def convert_ascii_bytes_to_bytes(ascii_data):
        '''
        This is the inverse function for convert_bytes_to_ascii_bytes. 
        Converts base85 encoding to bytes again
        '''
        return base64.b85decode(ascii_data)

    @staticmethod
    def create_SMS_test_connection():
        handler1 = SMS_handler(twilio_account_info.account1_SID_token_number, 
                               twilio_account_info.account2_SID_token_number[2])
        handler2 = SMS_handler(twilio_account_info.account2_SID_token_number, 
                               twilio_account_info.account1_SID_token_number[2])
        return handler1, handler2

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
        self.__remote.__add_to_buffer(SMS_handler.convert_bytes_to_ascii_bytes(data))

    def __add_to_buffer(self, data):
        self.__buffer += SMS_handler.convert_ascii_bytes_to_bytes(data)

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
    # This uses some of the free money in the trial accounts, so use sparingly
    #handler1,handler2 = SMS_handler.create_SMS_test_connection()
    handler1, handler2 = Fake_SMS_handler.create_fake_connection()
    
    handler1.sendall(b'To handler2 from handler1')
    handler2.sendall(b'To handler1 from handler2')
    #sleep(20) # Sleep needed when using real SMS connect
    print(handler2.recv())
    print(handler1.recv())
    #
    test_bytes = b'Test bytes'
    encoded = SMS_handler.convert_bytes_to_ascii_bytes(test_bytes)
    decoded = SMS_handler.convert_ascii_bytes_to_bytes(encoded)
    print(encoded)
    print(decoded)
