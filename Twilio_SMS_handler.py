import twilio_account_info
from twilio.rest import Client
from time import sleep
import datetime
import sys
import re
import pytz
import helper_functions
from helper_functions import recvall

class Twilio_SMS_handler(object):
    def __init__(self, account_info, send_number):
        self.__client = Client(account_info[0], account_info[1])
        self.__this_number = account_info[2]
        self.__send_number = send_number
        self.__buffer = b''
        self.__last_time_checked = pytz.UTC.localize(datetime.datetime.utcnow())
        self.__regex = re.compile(r'^Sent from your Twilio trial account - ')

    def sendall(self, data):
        print(f'Twilio sendall -- {data}')
        self.__client.messages.create(
                     body=helper_functions.convert_bytes_to_ascii_bytes(data),
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
                print(f'Twilio recv -- {message.body}')
                self.__buffer += helper_functions.convert_ascii_bytes_to_bytes(self.__regex.sub('', message.body))
            self.__last_time_checked = current_time

        ret_val = self.__buffer[:min([num_bytes, len(self.__buffer)])]
        self.__buffer = self.__buffer[len(ret_val):]
        return ret_val

    @staticmethod
    def create_SMS_test_connection():
        handler1 = Twilio_SMS_handler(twilio_account_info.account1_SID_token_number, 
                               twilio_account_info.account2_SID_token_number[2])
        handler2 = Twilio_SMS_handler(twilio_account_info.account2_SID_token_number, 
                               twilio_account_info.account1_SID_token_number[2])
        return handler1, handler2

if __name__ == '__main__':
    # This uses some of the free money in the trial accounts, so use sparingly
    handler1,handler2 = Twilio_SMS_handler.create_SMS_test_connection()
    
    handler1_send_bytes = b'To handler2 from handler1'
    handler2_send_bytes = b'To handler1 from handler2'
    handler1.sendall(handler1_send_bytes)
    handler2.sendall(handler2_send_bytes)

    assert recvall(handler2, len(handler1_send_bytes)) == handler1_send_bytes
    assert recvall(handler1, len(handler2_send_bytes)) == handler2_send_bytes
    print('Passed Test!')
