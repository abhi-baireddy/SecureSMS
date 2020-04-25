from time import sleep, time
import datetime
import sys
from ipaddress import IPv4Address
from pyairmore.request import AirmoreSession
import pyairmore.services.messaging
from pyairmore.data.messaging import MessageType
from pyairmore.services.messaging import MessagingService
from helper_functions import format_phone_number
import re

class Airmore_SMS_handler(object):
    def __init__(self, phone_IP, send_number):
        self.__send_number = format_phone_number(send_number)
        self.__session = AirmoreSession(IPv4Address(phone_IP))
        self.__correct_direction = lambda x: x.type == MessageType.RECEIVED
        assert self.__session.is_server_running
        assert self.__session.request_authorization()
        self.__service = MessagingService(self.__session)
        self.__initialization_time = datetime.datetime.now()
        self.__chat_id = None
        self.__chat_id = self.__get_chat_id()
        self.__buffer = b''
        self.__already_read = set()
        # Add new messages to already read...
        self.get_new_messages()

    def send(self, message):
        assert isinstance(message, str)
        self.__service.send_message(self.__send_number, message)
    
    def get_new_messages(self):
        chat_id = self.__get_chat_id()
        new_messages = []
        if chat_id != None:
            messages = self.__service.fetch_chat_history(message_or_id=chat_id, limit=50)
            for message in messages:
                if self.__correct_direction(message) and not (message.id, message.content) in self.__already_read:
                    new_messages.append(message.content)
            self.__already_read = set((message.id, message.content) for message in messages)
        return new_messages

    def __get_chat_id(self):
        if self.__chat_id != None:
            return self.__chat_id

        for message in self.__service.fetch_message_history():
            if format_phone_number(message.phone) == self.__send_number:
                self.__chat_id = message.id
            
        return self.__chat_id

    @staticmethod
    def create_test_connection():
        handler1 = Airmore_SMS_handler('192.168.1.22', '8016605023')
        handler2 = Airmore_SMS_handler('192.168.1.23', '8016436371')
        return handler1, handler2

if __name__ == '__main__':
    handler1,handler2 = Airmore_SMS_handler.create_test_connection()
    
    handler1_send_bytes = 'To handler2 from handler1'
    handler2_send_bytes = 'To handler1 from handler2'
    handler1.send(handler1_send_bytes)
    handler2.send(handler2_send_bytes)
    
    while True:
        handler1_messages = handler1.get_new_messages()
        if len(handler1_messages) > 0:
            break
        else:
            sleep(1)

    while True:
        handler2_messages = handler2.get_new_messages()
        if len(handler2_messages) > 0:
            break
        else:
            sleep(1)
            
    assert handler1_messages[0] == handler2_send_bytes
    assert handler2_messages[0] == handler1_send_bytes
    print('Passed Test!')
