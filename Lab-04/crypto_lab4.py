"""Лабораторна №4: AES-GCM, RSA-PSS, HMAC-SHA256.
Запуск: python crypto_lab4.py
"""
import base64
import os
import hmac as std_hmac
import hashlib

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def run_demo():
    message = 'Лабораторна робота №4. Захист мережевих даних.'.encode('utf-8')
    print('Повідомлення:', message.decode('utf-8'))

    # AES-256-GCM: ключ 32 байти, nonce 12 байт, новий для кожного шифрування цим ключем.
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad = b'lab4:example:v1'
    ciphertext = AESGCM(key).encrypt(nonce, message, aad)
    restored = AESGCM(key).decrypt(nonce, ciphertext, aad)
    print('\n[AES-256-GCM]')
    print('Nonce (Base64):', b64(nonce))
    print('Ciphertext + tag (Base64):', b64(ciphertext))
    print('Розшифрування успішне:', restored == message)

    damaged = bytearray(ciphertext)
    damaged[0] ^= 0x01
    try:
        AESGCM(key).decrypt(nonce, bytes(damaged), aad)
        print('ПОМИЛКА: зміну шифротексту не виявлено')
    except InvalidTag:
        print('Підміна біта у шифротексті: виявлена (InvalidTag)')

    # RSA-PSS із SHA-256: генерація ключів для навчального прикладу.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    signature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    print('\n[RSA-PSS / SHA-256]')
    try:
        public_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print('Перевірка підпису оригіналу: успішна')
    except InvalidSignature:
        print('ПОМИЛКА: правильний підпис відхилено')
    try:
        public_key.verify(signature, message + b'!', padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print('ПОМИЛКА: підміну повідомлення не виявлено')
    except InvalidSignature:
        print('Перевірка підпису зміненого повідомлення: відхилена (InvalidSignature)')

    # HMAC-SHA256: ключ має залишатися секретним; порівняння постійного часу.
    hmac_key = os.urandom(32)
    tag = std_hmac.new(hmac_key, message, hashlib.sha256).digest()
    valid = std_hmac.compare_digest(tag, std_hmac.new(hmac_key, message, hashlib.sha256).digest())
    invalid = std_hmac.compare_digest(tag, std_hmac.new(hmac_key, message + b'!', hashlib.sha256).digest())
    print('\n[HMAC-SHA256]')
    print('HMAC (Base64):', b64(tag))
    print('Оригінальне повідомлення прийнято:', valid)
    print('Змінене повідомлення прийнято:', invalid)
    assert restored == message and valid and not invalid
    print('\nУсі навчальні перевірки завершені.')


if __name__ == '__main__':
    run_demo()
