import binascii
import pefile
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA

def extract_data(filename):
    pe = pefile.PE(filename)
    for section in pe.sections:
        if ".data" in section.Name.decode(encoding='utf-8').rstrip('x00'):
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)
def data_decryptor(rc4key, encrypted_config):
    rc4_cipher = ARC4.new(rc4key)
    decrypted_config = rc4_cipher.decrypt(encrypted_config)
    return decrypted_config

def main():
    filename = input("Filename: ")
    datasec = extract_data(filename)
    datasec2 = datasec[16:]
    key = datasec2[:8]
    encrypted_data = binascii.hexlify(datasec2[8:256])  #hexlify translates bin data to hex format
    hashed_key = SHA.new(key).hexdigest()       #Generates a hexidecimal SHA1 hash
    true_key = hashed_key[:10]          #collect only the first 10 hexadecimal (5 bytes)
    c2_config = data_decryptor(binascii.unhexlify(true_key), binascii.unhexlify(encrypted_data))
    print(c2_config.decode('uft-8'))

if __name__ == '__main__':
    main()
