import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import hmac

_BLOCK_SIZE = 16
_KEY = "new test 110"
_INFO = "AuthorizationKey"

class EncryptDecrypt:
    
    def get_key() -> str:
        return _KEY
    
    def get_block_size() -> str:
        return _BLOCK_SIZE
    
    def get_info() -> str:
        return _INFO

    def encrypt_str(self, raw:str) -> bytes:
        
        keySalt = self.generate_random_key(EncryptDecrypt.get_block_size())
        key = self.hash_hkdf(EncryptDecrypt.get_key(), keySalt, EncryptDecrypt.get_info(), EncryptDecrypt.get_block_size())
        iv = self.generate_random_key(EncryptDecrypt.get_block_size())       

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        raw = _pad(raw)

        encrypted = iv + encryptor.update(raw.encode('latin-1')) + encryptor.finalize()

        hash = hmac.new(key, encrypted, hashlib.sha256).hexdigest()

        hashed = bytes(hash, 'latin-1') + encrypted

        encrypted_data = keySalt + hashed
        
        return encrypted_data

    def decrypt_str(self, enc:bytes) -> str:
        
        enc = base64.b64decode(enc)
        iv = enc[0:EncryptDecrypt.get_block_size()]                
        keySalt = enc[0:EncryptDecrypt.get_block_size()]
        enc = enc[EncryptDecrypt.get_block_size():]       

        key = self.hash_hkdf(EncryptDecrypt.get_key(), keySalt, EncryptDecrypt.get_info(), EncryptDecrypt.get_block_size())

        test = hmac.new(key, enc, hashlib.sha256).hexdigest()

        hashLen = len(test)
        if hashLen > len(enc):
            raise Exception("Invalid Hash Size")
        
        hash = enc[0:hashLen]
        pureData = enc[hashLen:]

        calculatedHash = hmac.new(key, pureData, hashlib.sha256).hexdigest()
        
        if bytes(calculatedHash, 'latin-1') != hash:
            raise Exception("Invalid Hash") 

        iv = pureData[0:EncryptDecrypt.get_block_size()]
        encrypted = pureData[EncryptDecrypt.get_block_size():]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        raw = decryptor.update(encrypted) + decryptor.finalize()
        raw = raw.decode('latin-1')
        return _unpad(raw)
    
    def generate_random_key(self, keySize) -> str:
        return (base64.b64encode(os.urandom(int(keySize))))[0:EncryptDecrypt.get_block_size()]
    
    def hash_hkdf(self, inputKey, salt, info, length) -> str:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=bytes(info, 'utf8'),
        )
        return hkdf.derive(bytes(inputKey, 'utf8'))
    
    def encrypt_file(self, data:bytes) -> bytes:
        return  self.encrypt_str(str(data).encode("raw_unicode_escape").decode("unicode_escape")[2:-1])
    
    def decrypt_file(self, data:bytes) -> bytes:
        return bytes(self.decrypt_str(base64.b64encode(data)), 'latin-1')
    
    def encrypt_and_save_file(self, origin:str, destination_encrypted_file:str) -> bool:
        original_file = open(origin, "rb")
        original_file_content = original_file.read()
        original_file.close()

        destination_file = open(destination_encrypted_file, "w+b")
        encrypted_file_content = self.encrypt_file(original_file_content)
        destination_file.write(encrypted_file_content)
        destination_file.close()

        return True
    
    def decrypt_and_save_file(self, origin_encrypted_file:str, destination:str) -> bool:
        encrypted_file = open(origin_encrypted_file, "rb")
        encrypted_file_content = encrypted_file.read()
        encrypted_file.close()

        destination_file = open(destination, "w+b")
        decrypted_file_content = self.decrypt_file(encrypted_file_content)
        destination_file.write(decrypted_file_content)
        destination_file.close()

        return True
    
    def check_file_content(self, file_one_path:str, file_two_path:str) -> bool:
            file_one = open(file_one_path, "rb")
            file_one_content = file_one.read()
            file_one.close()

            file_two = open(file_two_path, "rb")
            file_two_content = file_two.read()
            file_two.close()

            assert file_one_content == file_two_content
            
            return True

def _pad(s:str) -> str:
    padding = (EncryptDecrypt.get_block_size() - (len(s) % EncryptDecrypt.get_block_size()))
    return s + padding * chr(padding)

def _unpad(s:str) -> str:
    return s[:-ord(s[len(s)-1:])]