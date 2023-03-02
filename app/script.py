#!/usr/bin/env python3
import tests
print('Running tests...')
'''
assert tests.test_encrypt_and_decrypt_works() == True
assert tests.test_encrypt_and_decrypt_works() == True
assert tests.test_encrypted_php_is_decrypted_with_py() == True
assert tests.test_encrypted_py_file_is_decrypted_with_py() == True
assert tests.test_encrypted_php_file_is_decrypted_with_py() == True
'''
tests.test_encrypt_files_in_dir()
tests.test_decrypt_files_in_dir()
tests.tests_if_the_contents_of_the_decrypted_files_are_the_same_as_the_original_files()
print('Finished with NO ERRORS.')