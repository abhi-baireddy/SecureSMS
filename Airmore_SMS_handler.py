from time import sleep
import datetime
import sys
from ipaddress import IPv4Address
from pyairmore.request import AirmoreSession
import pyairmore.services.messaging
from pyairmore.data.messaging import MessageType
from pyairmore.services.messaging import MessagingService
import helper_functions


class Airmore_SMS_handler(object):
    def __init__(self, phone_IP, send_number):
        self.__send_number = helper_functions.format_phone_number(send_number)
        self.__session = AirmoreSession(IPv4Address(phone_IP))
        self.correct_direction = lambda x: x.type == MessageType.RECEIVED
        assert self.__session.is_server_running
        assert self.__session.request_authorization()
        self.__service = MessagingService(self.__session)
        self.__initialization_time = datetime.datetime.now()
        self.__chat_id = None
        self.__last_received_message = None
        self.__chat_id, self.__last_received_message = self.__get_chat_id_and_last_message()
        self.__buffer = b''

    def sendall(self, data):
        assert isinstance(data, bytes)
        self.__service.send_message(self.__send_number, helper_functions.convert_bytes_to_ascii_bytes(data).decode())
    
    def recv(self, num_bytes=sys.maxsize):
        chat_id, last_message = self.__get_chat_id_and_last_message()
        if len(self.__buffer) < num_bytes and chat_id != None:
            for message in filter(self.correct_direction, reversed(self.__service.fetch_chat_history(message_or_id=chat_id, limit=30))):
                if message > last_message:
                    self.__buffer += helper_functions.convert_ascii_bytes_to_bytes(message.content.encode())
                    self.__last_received_message = message

        ret_val = self.__buffer[:min([num_bytes, len(self.__buffer)])]
        self.__buffer = self.__buffer[len(ret_val):]
        return ret_val

    def __get_chat_id_and_last_message(self):
        if self.__chat_id != None:
            return self.__chat_id, self.__last_received_message

        chat_id, last_received_message = None, None
        for message in filter(self.correct_direction, self.__service.fetch_message_history()):
            if helper_functions.format_phone_number(message.phone) == self.__send_number:
                chat_id = message.id
                if message.datetime < self.__initialization_time:
                    last_received_message = message
                else:
                    for message in filter(self.correct_direction, reversed(self.__service.fetch_chat_history(message_or_id=chat_id, limit=30))):
                        if message.datetime > self.__initialization_time:
                            self.__buffer += helper_functions.convert_ascii_bytes_to_bytes(message.content.encode())
                            last_received_message = message
                
        return chat_id, last_received_message

if __name__ == '__main__':
    handler1 = Airmore_SMS_handler('192.168.1.16', '8016436371')
    sleep(2)
    handler1.sendall(b'Testing1')
    sleep(2)
    handler1.sendall(b'Testing2')
    sleep(5)
    assert handler1.recv() == b'Testing1Testing2'
