from flask import Flask
import os
import base64
import random
import string
from classes.EncryptDecrypt import EncryptDecrypt
import tests

app = Flask(__name__)

@app.route("/")
def hello():
   
    web_return = "Python Tests: <br><br>"

    web_return+= "Secret Key: " + EncryptDecrypt.get_key() + "<br><br>"

    web_return+= "Test: Assert encrypt and decrypt with Python works: "
    if tests.test_encrypt_and_decrypt_works() == True:
        web_return+= "true<br><br>"

    web_return+= "Test: Assert PHP encrypted text is decrypted with Python: "
    if tests.test_encrypted_php_is_decrypted_with_py() == True:
        web_return+= "true<br><br>"

    web_return+= "Test: Assert Python encrypted file is decrypted with Python: "
    if tests.test_encrypted_py_file_is_decrypted_with_py() == True:
        web_return+= "true<br><br>"

    web_return+= "Test: Assert PHP encrypted file is decrypted with Python: "
    if tests.test_encrypted_php_file_is_decrypted_with_py() == True:
        web_return+= "true<br><br>"
       
    return web_return

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True,host='0.0.0.0',port=port)