# SecureSMS
Network Security class project

Install Dependencies:
pip install twilio

SMS Info:
SMS uses 160 bytes per message. Twilio prepends 38 bytes to each of our messages, leaving 122 bytes. 
SMS also only accepts ASCII characters, so we'll need to encode our bytes as ASCII characters. We will
use base85 encoding which converts every 4 bytes into 5 ASCII characters, which leaves us with 97 bytes
per SMS message.

Header:
Each message will have a short header with the following information
1 Byte Protocol Type -- Some constant value
2 Byte Version Number -- Major Minor version (0.0 for now)
1 Byte Message Type -- Byte representing step in handshake or data message
1 Byte message length -- Length of message after header

This leaves us with 92 data bytes

Protocol:
Alice sends two messages with her 1024-bit RSA public key with a SHA1 
    signing from her network provider. Each message has a different
    message type to order them properly as they arrive.
Bob sends two messages with 1. diffie-hellman number encrypted with
    Alice's public key, and 2. his signed public key
Alice sends Bob one message with a diffie-hellman number encrypted 
    with his public key

Alice and Bob use the two parts of the diffie-hellman exchange to 
    generate a 128-bit AES key with will be used with AES in ECB
    mode. ECB was chosen instead of CBC so that if any messages
    are dropped by AES then other messages can still be decrypted.