import os
import base64
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from alive_progress import alive_bar
import argon2


class Chaes:
    AES_header = f"Encrypted using Chaes. DO NOT TAMPER WITH.  |  Made by therealOri  |  {os.urandom(8)}"
    AES_header = bytes(AES_header, 'utf-8')

    chacha_header = b"ChaCha real smooth~ dada da dada da"
    salt = get_random_bytes(32)





    def clear(self):
        os.system("clear||cls")


    def keygen(self, master):
        if len(master) < 100:
            self.clear()
            input('Password/characters used must be 100 characters in length or more!\n\nPress "eneter" to continue...')
            self.clear()
            return None
        else:
            salt = os.urandom(16)

            # derive | DO NOT MESS WITH...unless you know what you are doing and or have more than 8GB of ram to spare and a really good CPU.
            print("Generating key...")
            with alive_bar(0) as bar:
                key = argon2.hash_password_raw(
                    time_cost=16,
                    memory_cost=2**20,
                    parallelism=4,
                    hash_len=32,
                    password=master,
                    salt=salt,
                    type=argon2.Type.ID
                )
                bar()
            self.clear()
            return key #returns bytes. You will need to base64 encode them yourself if you want a "shareable key"



    # AES functions
    def aes_enc(self, *, enc_data, key):
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(self.AES_header)
        ciphertext, tag = cipher.encrypt_and_digest(enc_data)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        json_v = [ base64.b64encode(x).decode('utf-8') for x in [cipher.nonce, self.AES_header, ciphertext, tag ]]
        result = json.dumps(dict(zip(json_k, json_v)))
        result_bytes = bytes(result, 'utf-8')
        b64_result = base64.b64encode(result_bytes)
        return b64_result.decode()


    def aes_dcr(self, *, dcr_data, key):
        try:
            json_input = base64.b64decode(dcr_data)
            b64j = json.loads(json_input)
            json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
            jv = {k:base64.b64decode(b64j[k]) for k in json_k}

            cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
            cipher.update(jv['header'])
            plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
            return plaintext
        except (ValueError, KeyError) as e:
            print(f'Oops, an error has occured: "{e}".\n')
            input("Incorrect data given, or Data has been tampered with. Can't decrypt.\n\nPress 'enter' to continue...")
            self.clear()
            return None



    # helper functions
    def base64_to_hex(self, base64_string):
        decoded_bytes = base64.b64decode(base64_string)
        hex_string = binascii.hexlify(decoded_bytes)
        return hex_string.decode()

    def hex_to_base64(self, hex_string):
        hex_bytes = bytes.fromhex(hex_string)
        base64_string = base64.b64encode(hex_bytes)
        return base64_string.decode()




    # ChaCha functions
    def encrypt(self, plaintext, eKey):
        data_enc = self.aes_enc(enc_data=plaintext, key=eKey)
        data_enc = bytes(data_enc, 'utf-8')

        cipher = ChaCha20_Poly1305.new(key=self.salt)
        cipher.update(self.chacha_header)
        ciphertext, tag = cipher.encrypt_and_digest(data_enc)

        jk = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = [ base64.b64encode(x).decode('utf-8') for x in (cipher.nonce, self.chacha_header, ciphertext, tag) ]
        result = json.dumps(dict(zip(jk, jv)))
        result_bytes = bytes(result, 'utf-8')
        b64_result = base64.b64encode(result_bytes)
        final_result = self.base64_to_hex(b64_result)
        return final_result


    def decrypt(self, dKey, json_input, salt):
        try:
            b64 = json.loads(json_input)
            jk = [ 'nonce', 'header', 'ciphertext', 'tag' ]
            jv = {k:base64.b64decode(b64[k]) for k in jk}

            cipher = ChaCha20_Poly1305.new(key=salt, nonce=jv['nonce'])
            cipher.update(jv['header'])
            plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        except (ValueError, KeyError):
            print("Incorrect decryption")
            return None
        decrypted_message = self.aes_dcr(dcr_data=plaintext, key=dKey)
        return decrypted_message





if __name__ == '__main__':
    print(f'{__name__} has been ran directly.')




