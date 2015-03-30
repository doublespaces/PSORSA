# PSORSA
PSO2JP RSA Decryption

This program was written using the Windows Crypto API for the purpose of using a PEM 
format private key to decrypt a data packet payload encrypted with RSA. This decryptor 
works in conjunction with the Phantasy Star Online 2 JP software and a controlled 
public private key pair. Credits go to the Polaris Team and CyberKitsune for the RSA 
Public Key Injector. If a new public key is used(Please see project PSO2Proxy for 
details), the source must be edited to include a modifed version of the associated private key 
created with the PSO2Proxy project. To modify this key use the following command:

openssl rsa -in myKey.pem -out modifiedprivkey.pem

Copy the contents of "modifiedprivkey.pem" into the source for decryption.

In addition, a file named "new128.bin" must be included in the working directory, which 
includes only the 0x80 bytes of RSA encrypted data. You can find this data through 
a packet log of a PSO2 client running through the PSO2Proxy software.
