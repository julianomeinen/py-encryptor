import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import hmac
from mnemonic import Mnemonic

class EncryptDecrypt:
    
    def __init__(self) -> None:
        self._BLOCK_SIZE = 16
        self._KEY = "new test 110"
        self._INFO = "AuthorizationKey"
        self.mnemo = Mnemonic("english")

    def set_key(self, key) -> str:
        self._KEY = key   

    def get_key_by_twenty_four_words(self, twenty_four_words) -> str:
        #twenty_four_words = "base depart together agent relief vivid slide smile amount tent orient magic fatigue metal steak marriage country today grain cruel bicycle tomato problem real"
        entropy = self.mnemo.to_seed(twenty_four_words)
        return entropy.hex()

    def generate_twenty_four_words(self, passphrase=""):
        words = self.mnemo.generate(strength=256)
        seed = self.mnemo.to_seed(words, passphrase)
        entropy = self.mnemo.to_entropy(words)
        return {'words': words, 'seed': seed.hex(), 'entropy': entropy.hex()}

    def get_block_size_key(self) -> str:
        return self._BLOCK_SIZE

    def encrypt_str(self, raw:str) -> bytes:
        
        keySalt = self.generate_random_key(self._BLOCK_SIZE)
        key = self.hash_hkdf(self._KEY, keySalt, self._INFO, self._BLOCK_SIZE)
        iv = self.generate_random_key(self._BLOCK_SIZE)       

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
        iv = enc[0:self._BLOCK_SIZE]                
        keySalt = enc[0:self._BLOCK_SIZE]
        enc = enc[self._BLOCK_SIZE:]       

        key = self.hash_hkdf(self._KEY, keySalt, self._INFO, self._BLOCK_SIZE)

        test = hmac.new(key, enc, hashlib.sha256).hexdigest()

        hashLen = len(test)
        if hashLen > len(enc):
            raise Exception("Invalid Hash Size")
        
        hash = enc[0:hashLen]
        pureData = enc[hashLen:]

        calculatedHash = hmac.new(key, pureData, hashlib.sha256).hexdigest()
        
        if bytes(calculatedHash, 'latin-1') != hash:
            raise Exception("Invalid Hash") 

        iv = pureData[0:self._BLOCK_SIZE]
        encrypted = pureData[self._BLOCK_SIZE:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        raw = decryptor.update(encrypted) + decryptor.finalize()
        raw = raw.decode('latin-1')
        return _unpad(raw)
    
    def generate_random_key(self, keySize) -> str:
        return (base64.b64encode(os.urandom(int(keySize))))[0:self._BLOCK_SIZE]
    
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
    encrypt = EncryptDecrypt()
    padding = (encrypt.get_block_size_key() - (len(s) % encrypt.get_block_size_key()))
    return s + padding * chr(padding)

def _unpad(s:str) -> str:
    return s[:-ord(s[len(s)-1:])]