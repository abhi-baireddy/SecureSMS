# SecureSMS
Network Security class project

Install Dependencies:
pip install pyopenssl pyairmore

SMS Info:
SMS uses 160 bytes per message. We will base85 encoding which converts every 4 bytes into 5 ASCII characters, 
which leaves us with 128 bytes per SMS message.

**Header**:
Each message will have a short header with the following information:  
* 1 Byte Protocol Type -- Some constant value  
* 2 Byte Version Number -- Major Minor version (0.0 for now)  
* 1 Byte Message Type -- Byte representing step in handshake or data message  
* 1 Byte message length -- Length of message after header  

This leaves us with 121 data bytes

**Protocol**:
Alice sends four messages with her 1024-bit RSA public key with a SHA1 
    RSA signing from her network provider. Each message has a different
    message type to order them properly as they arrive.
Bob sends four messages with   
1. diffie-hellman number encrypted with Alice's public key, and    
2. his signed public key  

Alice sends Bob two messages with a diffie-hellman number encrypted with his public key. Alice and Bob use the two parts of the diffie-hellman exchange to generate a 256-bit AES key and initialization vector that will be used with AES in CBC mode. CBC was chosen of over ECB to reduce
the ability of an adversary to decipher previously seen blocks.
