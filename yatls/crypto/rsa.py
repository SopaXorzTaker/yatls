import os


def rsa_pkcs1_encrypt(plaintext, modulus, exponent):
    # RSA encryption

    # Find the size of the modulus
    k = 0
    while 256**k < modulus:
        k += 1

    # Make sure the padding string doesn't contain any zeros
    while True:
        padding_string = os.urandom(k-3-len(plaintext))
        if b"\x00" not in padding_string:
            break

    padded_plaintext = b"\x00" + b"\x02" + padding_string + b"\x00" + plaintext

    m = int.from_bytes(padded_plaintext, "big")
    ciphertext = pow(m, exponent, modulus).to_bytes(k, "big")

    return ciphertext


def rsa_pkcs1_verify_decrypt(ciphertext, modulus, exponent, plaintext_length):
    c = int.from_bytes(ciphertext, "big")

    # RSA decryption
    padded_plaintext = pow(c, exponent, modulus).to_bytes(len(ciphertext), "big")

    # Un-pad the plaintext
    assert padded_plaintext[0] == 0

    block_type = padded_plaintext[1]
    assert block_type in [0x00, 0x01]

    padding_end_index = len(padded_plaintext) - 3 - plaintext_length//8

    for i in range(2, padding_end_index):
        assert padded_plaintext[i] == 0xFF if block_type == 0x01 else 0x00

    assert padded_plaintext[padding_end_index] == 0x00

    plaintext = padded_plaintext[padding_end_index + 1:]

    return plaintext
