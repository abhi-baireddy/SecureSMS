from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import re
import time
import random

# Generates a public and private key for RSA encryption/decryption
def generate_RSA_public_private_pair():
    pub_private_key = crypto.PKey()
    pub_private_key.generate_key(crypto.TYPE_RSA, 1024)
    public_key = serialization.load_pem_public_key(
        crypto.dump_publickey(crypto.FILETYPE_PEM, pub_private_key), 
        backend=default_backend())
    private_key = serialization.load_pem_private_key(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, pub_private_key),
        password=None, 
        backend=default_backend())
    return public_key, private_key

# Encrypts bytes using an RSA public key
def RSA_encrypt(data, pub_key):
    return pub_key.encrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

# Decrypts bytes using an RSA private key
def RSA_decrypt(data, priv_key):
    return priv_key.decrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

def diffie_hellman_public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint)

def bytes_to_diffie_hellman_public_key(pub_bytes):
    return ec.EllipticCurvePublicKey\
        .from_encoded_point(ec.SECP384R1(), pub_bytes)

# Dumps public key as bytes object (140 bytes)
def bytes_to_public_key(public_key_bytes):
    return serialization.load_der_public_key(
        public_key_bytes, 
        backend=default_backend())

# Reads public key as bytes object (140 bytes)
def public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1)

# Generates a random bytes object with the given length        
def generate_random_bytes(length):
    return bytes(bytearray(random.getrandbits(8) for _ in range(length)))

# Returns diffie hellman value and a function
# to calculate the shared secret from the remote
# end's diffie hellman value
def diffie_hellman():
    private_key = ec.generate_private_key(
     ec.SECP384R1(), default_backend())
    return private_key.public_key(), lambda remote_public_key: private_key.exchange(ec.ECDH(), remote_public_key)

# Creates an encryptor and encryptor for AES in ECB mode
def AES_ECB(key):
    cipher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
    return (lambda plaintext : cipher.encryptor().update(plaintext)), (lambda ciphertext : cipher.decryptor().update(ciphertext))


def convert_bytes_to_ascii_bytes(data):
    '''
    SMS can only send ASCII bytes, so this will base85 encode all the
    bytes so they can be sent properly. This will unfortunately take
    up more space per message. yENC is another format that has more
    space efficiency, but we'd need to pull in another module for that.
    '''
    return base64.b85encode(data)

def convert_ascii_bytes_to_bytes(ascii_data):
    '''
    This is the inverse function for convert_bytes_to_ascii_bytes. 
    Converts base85 encoding to bytes again
    '''
    return base64.b85decode(ascii_data)

def pack_bytes(parts):
        ret_val = b''
        for part in parts:
            actual_part, num_bytes = part if isinstance(part, tuple) else (part, 1)
            assert isinstance(num_bytes, int)
            if isinstance(actual_part, bytes):
                ret_val += actual_part
            else:
                ret_val += int.to_bytes(int(actual_part), num_bytes, 'big')
        return ret_val 

# converts a list of bytes to a list of ints
def bytes_to_ints(bytes_list):
    return [int.from_bytes(part, 'big') for part in bytes_list]

# Uses a loop to make sure that the requested number of bytes are received
def recvall(SMS_handler, num_bytes, timeout_sec=30):
    result = b''
    start = time.time()
    while len(result) < num_bytes:
        if (time.time() - start) < timeout_sec:
            result += SMS_handler.recv(num_bytes - len(result))
        else:
            raise TimeoutError
    return result

def format_phone_number(phone_number):
	#strip all characters out except digits
	if phone_number is None:
		return ''
	ret_val = re.sub('[^0-9]','', phone_number)
	#if country code is included for USA, remove it
	if (len(ret_val) == 11) and (ret_val[0] == "1"):
		ret_val = ret_val[1:]
	#if phone number is invalid, print an error message and return empty string
	if (len(ret_val) < 10) and (ret_val != ''):
		ret_val = ''
	return ret_val

if __name__ == '__main__':
    pub, priv = generate_RSA_public_private_pair()
    pub_bytes = public_key_to_bytes(pub)
    print(pub_bytes)
    print(len(pub_bytes))
    pub_new = bytes_to_public_key(pub_bytes)
    pub_bytes_new = public_key_to_bytes(pub)
    assert pub_bytes == pub_bytes_new

    test_bytes = b'Test bytes'
    encoded = convert_bytes_to_ascii_bytes(test_bytes)
    decoded = convert_ascii_bytes_to_bytes(encoded)
    print(encoded)
    print(decoded)
    assert test_bytes == decoded
