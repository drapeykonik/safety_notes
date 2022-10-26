import random

from cryptography.hazmat.primitives.ciphers import modes, algorithms, base
import binascii


def encrypt_note(shared_secret, name, content, iv):
    password = shared_secret.to_bytes(128, 'big')
    #iv = random.randbytes(16)
    cipher = base.Cipher(
        algorithms.IDEA(binascii.unhexlify(password)),
        modes.CFB(binascii.unhexlify(iv))
    )
    encryptor = cipher.encryptor()
    name = str(encryptor.update(name) + encryptor.finalize())
    if content is not None:
        content = str(encryptor.update(content) + encryptor.finalize())
    return name, content


def decrypt_note(shared_secret, name, content, iv):
    password = shared_secret.to_bytes(128, 'big')
    #iv = random.randbytes(16)
    cipher = base.Cipher(
        algorithms.IDEA(binascii.unhexlify(password)),
        modes.CFB(binascii.unhexlify(iv))
    )
    decryptor = cipher.decryptor()
    name = str(decryptor.update(eval(name)) + decryptor.finalize())
    content = str(decryptor.update(eval(content)) + decryptor.finalize())
    return name, content


def report_success(response, expected_code=200):
    ok = response.status_code == expected_code
    if 'message' in response.json() and response.json()['message'] == 'ECDH error':
        print('ECDH error')
        return False
    else:
        print('Successful' if ok else 'Failed')
    return ok
