from Crypto.Cipher import AES

from hashlib import pbkdf2_hmac

import getpass
import pyautogui

import random
import string
import time


def IV(length):
    letters_and_digits = string.ascii_letters + string.digits
    rand_string = ''.join(random.sample(letters_and_digits, length))
    return rand_string.encode()


def salt_generation():
    print('mouse\n3')
    time.sleep(1)
    print('2')
    time.sleep(1)
    print('1')
    time.sleep(1)
    print('start')

    coordinates = []
    salt = ''
    for c in range(32):
        point = pyautogui.position()  # Point(x,y)
        coordinates.append(bin(point[0] ^ point[1])[7])
        salt += coordinates[c]
        time.sleep(0.16)
    if len(salt) != 32:
        salt_generation()
    else:
        return salt


def key_generation(mode=0, pss=None, salt=None):
    if mode == 0:
        if pss is None:
            pss = getpass.getpass(prompt="Enter super secret password:")
            pss = pss.encode()
        if salt is None:
            salt = salt_generation()
            salt = salt.encode()

        key = pbkdf2_hmac('sha256', pss, salt, 100000)
        return salt, key

    elif mode == 1:
        pss = getpass.getpass(prompt="Enter super secret password:")
        pss = pss.encode()
        return pss


def encrypt(encrypted_file_name):
    salt, key = key_generation()

    vect = IV(16)

    cipher = AES.new(key, AES.MODE_CFB, vect)

    file = open(encrypted_file_name, 'rb')
    msg = file.read()

    hmac = pbkdf2_hmac('sha256', key, msg, 100000)

    ciphertext = cipher.encrypt(msg)

    encrypted_file = open('enc_' + encrypted_file_name, 'wb')

    encrypted_file.write(salt + hmac + vect + ciphertext)

    file.close()
    encrypted_file.close()

    return ciphertext


def decrypt(encrypted_file_name, decrypted_file_name, mode=1, sha256=100000):
    encrypted_file = open(encrypted_file_name, 'rb')
    decrypted_file = open(decrypted_file_name, 'wb')

    enc_text = encrypted_file.read()

    salt = enc_text[:32]
    vect = enc_text[64:-(len(enc_text) - 80)]
    ciphertext = enc_text[80:]

    pss = key_generation(1)
    key = pbkdf2_hmac('sha256', pss, salt, sha256)

    cipher = AES.new(key, AES.MODE_CFB, vect)
    plaintext = cipher.decrypt(ciphertext)

    hmac = pbkdf2_hmac('sha256', key, plaintext, sha256)

    if mode == 1:
        file_hmac = enc_text[32:-(len(enc_text) - 64)]
        if hmac == file_hmac:
            print('Данные не повреждены')
        else:
            print('Беда')

    decrypted_file.write(plaintext)

    decrypted_file.close()
    encrypted_file.close()

    return plaintext

encrypt('hmac.txt')
decrypt('enc_hmac.txt', 'dec_hmac.txt')


