
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

def gen_iv():

    return Random.new().read(16)

def key_from_string(string,length=None):
    if length:
        if length == 16:
            return hashlib.md5(str(string).encode('utf-8')).digest()
        if length <= 128:
            return hashlib.sha512(bytes(str(string)*length*21,'utf-8')).digest()[:length]
        else:
            raise Exception('Length should be less than or equal to 128!')
    else:
        return hashlib.sha512(bytes(str(string) * length * 21, 'utf-8')).digest()

def encrypt(b,keystring,IV=None):

    if not keystring:
        return b

    if type(b) == int:

        b = b.to_bytes(1,'little')

    key = key_from_string(str(keystring),16)
    IV = Random.new().read(16) if not IV else IV

    encryption_suite = AES.new(key, AES.MODE_CFB, IV)
    encrypted = encryption_suite.encrypt(b)

    return encrypted

def decrypt(b,keystring,IV):

    if not keystring:
        return b

    if type(b) == int:

        b = b.to_bytes(1,'little')

    key = key_from_string(str(keystring),16)
    IV = IV

    decryption_suite = AES.new(key, AES.MODE_CFB, IV)
    decrypted = decryption_suite.decrypt(b)

    return decrypted
