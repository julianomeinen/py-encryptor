import base64
import random
import string
from classes.EncryptDecrypt import EncryptDecrypt
import glob
import os

def test_encrypt_and_decrypt_works():
    encryptDecryp = EncryptDecrypt()
    text = "Python - Lorem Ipsum test " + ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    encripted_text = encryptDecryp.encrypt_str(text)
    decripted_text = encryptDecryp.decrypt_str(base64.b64encode(encripted_text))
    assert decripted_text == text
    return True

def test_encrypted_php_is_decrypted_with_py():
    encryptDecryp = EncryptDecrypt()
    text = "Q3hpbWF5Y1RBRFowNGp0cjUzM2JiYjViNjA2MzRmZmRlZmU3YTA5ZWI0M2I5OTZhMTIxYzRkODllZWU1ZWY0YmFmOTlhOWE4YzljNGE4OGNhcjdTS3ZwQ1I0RGhvQzVZajQ0JuI1i6sNmsFfY77WHFxOnhuorHH2Q6oVj+cF+XU="
    encripted_text = encryptDecryp.encrypt_str(text)
    decripted_text = encryptDecryp.decrypt_str(base64.b64encode(encripted_text))
    assert decripted_text == text
    return True

def test_encrypted_py_file_is_decrypted_with_py():
    encryptDecryp = EncryptDecrypt()
    
    original_file = open("files/tests/kratos-test-upload.txt", "rb")
    original_file_content = original_file.read()
    original_file.close()

    destination_file = open("files/tests/kratos-test-upload-py.txt", "w+b")
    destination_file.write(original_file_content)
    destination_file.close()

    original_py_file = open("files/tests/kratos-test-upload-py.txt", "rb")
    original_py_file_content = original_py_file.read()
    original_py_file.close()

    assert original_py_file_content == original_file_content    

    destination_encrypted_py_file = open("files/tests/kratos-test-upload-py-encrypted", "w+b")
    encrypted_py_content = encryptDecryp.encrypt_file(original_py_file_content)
    destination_encrypted_py_file.write(encrypted_py_content)
    destination_encrypted_py_file.close()

    assert original_py_file_content != encrypted_py_content

    py_encrypted_file = open("files/tests/kratos-test-upload-py-encrypted", "rb")
    py_encrypted_file_content = py_encrypted_file.read()
    py_encrypted_file.close()

    destination_file = open("files/tests/kratos-test-upload-decrypted-py.txt", "w+b")
    decrypt_file_content = encryptDecryp.decrypt_file(py_encrypted_file_content)
    destination_file.write(decrypt_file_content)
    destination_file.close()

    assert original_file_content == decrypt_file_content

    decrypted_file = open("files/tests/kratos-test-upload-decrypted-py.txt", "rb")
    decrypted_file_content = decrypted_file.read()
    decrypted_file.close()

    assert original_file_content == decrypted_file_content
    
    return True

def test_encrypted_php_file_is_decrypted_with_py():
    encryptDecryp = EncryptDecrypt()
    
    original_file = open("files/tests/kratos-test-upload-encrypted", "rb")
    original_file_content = original_file.read()
    original_file.close()

    destination_file = open("files/tests/kratos-test-upload-decrypted-py.txt", "w+b")
    decrypt_file_content = encryptDecryp.decrypt_file(original_file_content)
    destination_file.write(decrypt_file_content)
    destination_file.close()

    decrypted_file = open("files/tests/kratos-test-upload-encrypted", "rb")
    decrypted_file_content = decrypted_file.read()
    decrypted_file.close()

    assert original_file_content == decrypted_file_content
    return True


def test_encrypt_files_in_dir():
    encryptDecryp = EncryptDecrypt()
    for file in glob.glob("files/tests/*"):
        if os.path.isfile(file):
            name = file[file.rfind("/"):]
            encryptDecryp.encrypt_and_save_file(file, "files/tests/encrypted" + name + "-encrypted")
            print(file + " was encrypted as files/tests/encrypted" + name + "-encrypted")

def test_decrypt_files_in_dir():
    encryptDecryp = EncryptDecrypt()
    for file in glob.glob("files/tests/encrypted/*"):
        if os.path.isfile(file):
            name = file[file.rfind("/"):-10]
            encryptDecryp.decrypt_and_save_file(file, "files/tests/decrypted" + name)
            print(file + " was decrypted as files/tests/decrypted" + name)

def tests_if_the_contents_of_the_decrypted_files_are_the_same_as_the_original_files():
    encryptDecryp = EncryptDecrypt()
    for file in glob.glob("files/tests/*"):
        if os.path.isfile(file):
            name = file[file.rfind("/"):]
            encryptDecryp.check_file_content(file, "files/tests/decrypted" + name)
            print("The content of " + file + " is the same as the files/tests/decrypted" + name + "file.")