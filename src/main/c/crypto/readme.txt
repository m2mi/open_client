To generate a new certificate and associated private key:

  > openssl req -x509 -newkey rsa:4096 -keyout privKey.pem -out cert.pem -days 365 -sha256 -nodes
