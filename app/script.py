#!/usr/bin/env python3
import tests
print('Running tests...')
assert tests.test_encrypt_files_in_dir() == True
assert tests.test_decrypt_files_in_dir() == True
assert tests.tests_if_the_contents_of_the_decrypted_files_are_the_same_as_the_original_files() == True
assert tests.tests_twenty_four_words() == True
assert tests.tests_get_key_by_twenty_four_words() == True
print('Finished with NO ERRORS.')