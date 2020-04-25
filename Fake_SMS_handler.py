# A Fake SMS handler to be used for testing
class Fake_SMS_handler(object):
    def __init__(self):
        self.__buffer = []
        self.__remote = None

    def get_new_messages(self):
        ret_val, self.__buffer = self.__buffer, []
        return ret_val

    def send(self, message):
        self.__remote.__add_to_buffer(message)

    def __add_to_buffer(self, data):
        self.__buffer.append(data)

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
    
    handler1_send_bytes = 'To handler2 from handler1'
    handler2_send_bytes = 'To handler1 from handler2'
    handler1.send(handler1_send_bytes)
    handler2.send(handler2_send_bytes)
    assert handler1.get_new_messages()[0] == handler2_send_bytes
    assert handler2.get_new_messages()[0] == handler1_send_bytes
    print('Passed Test!')
