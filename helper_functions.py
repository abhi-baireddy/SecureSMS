from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

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



# Returns diffie hellman value and a function
# to calculate the shared secret from the remote
# end's diffie hellman value
def diffie_hellman(S, g, p):
    def get_bit(bits, n):
        return 1 if bits & (1 << n) else 0

    def expo(m, d, n):
        ret_val = 1
        for bit_i in reversed(range(d.bit_length())):
            ret_val *= ret_val
            ret_val = ret_val % n
            if get_bit(d, bit_i) == 1:
                ret_val *= m
                ret_val = ret_val % n
        return ret_val

    T = expo(g, S, p)
    def step_2(other_T):
        shared_secret = expo(other_T, S, p)
        return shared_secret
    return T, step_2

# Creates an encryptor and encryptor for AES in ECB mode
def AES_ECB(key):
    cipher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
    return (lambda plaintext : cipher.encryptor().update(plaintext)), (lambda ciphertext : cipher.decryptor().update(ciphertext))

if __name__ == '__main__':
    pub, priv = generate_RSA_public_private_pair()
    pub_bytes = public_key_to_bytes(pub)
    print(pub_bytes)
    print(len(pub_bytes))
    pub_new = bytes_to_public_key(pub_bytes)
    pub_bytes_new = public_key_to_bytes(pub)
    assert pub_bytes == pub_bytes_new
