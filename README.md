Secure-Echo
===========

Securing TCP connections using SSL. This program modifies the implementation of
the Echo program to use SSL. The functionalities implemented are:

1. The client authenticates the server before sending and receiving messages,
   which is performed by setting the list of trusted CA's in the client by 
   calling `SSL_CTX_load_verify_locations`. Then, the verification occurs during
   the SSL handshake (`connect` on client, `accept` on server)

2. Communication between client and server is encrypted using `SSL_read` and 
   `SSL_write` to perform the data exchange between client and server.

3. A new symmetric key is created every time the client connects to the server
   because the server will create a new SSL object every time a new client
   connects to it.

4. The client and server verify the data they are sent, since SSL uses data 
   digest and if the digest the receiver calculated from the message does not
   match the digest attached to the message, then the corrupted data will not
   be passed to the application. 