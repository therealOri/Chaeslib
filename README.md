# Chaeslib
A pypi package that uses AES-GCM and ChaCha20_Poly1305 encryption to encrypt and decrypt your data.
__ __

<br>
<br>

# About
This library was made possible beause of my project called [Chaes](https://github.com/therealOri/Chaes). It uses the same functinality here to encrypt and decrypt messages and files. I wanted that project to be more shareable so thus this lib/package was born. (I am still kinda new to making packages).
__ __


<br>
<br>

# Installation
```
virtualenv chaENV
source chaENV/bin/activate
pip install Chaeslib
```
> If you don't have `virtualenv` you can install it via `pip`. "`pip install virtualenv`".
__ __

<br>
<br>

# Example | Documentation
This very basic example is what I do to make things work and showcase how to use things. (Copy and pasting this code will give you something that works for encrypting messages.) If you replace the way to get a message with opening a file and getting bytes, then it can work for files as well. (It is up to you to optimize for large files.)
```python
from Chaeslib import Chaes
import base64



if __name__ == '__main__':
    # flag 1: decrypt  |  flag 2: encrypt
    flag = 2
    if flag == 1:
        chaes = Chaes()
        dKey = input("Encryption Key: ")
        dMessage = input("Encrypted Message: ")
        enc_message = chaes.hex_to_base64(dMessage)

        #Decode message and get salt and key after splitting on ":" to make a list.
        json_input = base64.b64decode(enc_message)
        key_and_salt = dKey.split(":")
        salt_1 = key_and_salt[1]
        key_0 = key_and_salt[0]

        salt = base64.b64decode(salt_1)
        key = base64.b64decode(key_0)

        cha_aes_crypt = chaes.decrypt(key, json_input, salt)
        chaes.clear()
        input(f'Here is your encrypted message: {cha_aes_crypt.decode()}\n\nPress "enter" to contine...')
        chaes.clear()


    if flag == 2:
        chaes = Chaes()
        message = input("Message to encrypt: ").encode()
        key_data = input("Data for key gen: ").encode()

        chaes.clear()
        eKey = chaes.keygen(key_data) #Returns bytes and will return "None" if what's provided is less than 100 characters.

        if not eKey:
            exit()

        save_me = base64.b64encode(eKey)
        bSalt = base64.b64encode(chaes.salt)
        master_key = f"{save_me.decode()}:{bSalt.decode()}"

        input(f'Save this key so you can decrypt later: {master_key}\n\nPress "enter" to contine...')
        chaes.clear()
        enc_msg = chaes.encrypt(message, eKey)
        print(enc_msg)

```
__ __

- chaes.clear()
> Clears your terminal

<br>

- chaes.encrypt(message, key)
> Encrypts bytes/data.

- > `message` is the bytes/data you want to encrypt.
- > `key` is the key that was generated by `chaes.keygen()`


<br>

- chaes.decrypt(key, json_input, salt)
> Decrypts your encrypted data/message.

- > `key` is the key that was used to encrypt your data.
- > `json_input` is the base64 decoed json data that has your encrypted data.
- > `salt` is the other half of the "key" that was used to encrypt your data.

<br>

- chaes.keygen(key_data)
> Generates a "key" to be used to encrypt your data. (uses argon2id)

- > `key_data` is just a bunch of keyboard mashing and spamming to get a bunch of garble to make a key. (You could use [Genter](https://github.com/therealOri/Genter) to make a key if you'd like.)
__ __

<br />
<br />
<br />


# Support  |  Buy me a coffee <3
Donate to me here:
> - Don't have Cashapp? [Sign Up](https://cash.app/app/TKWGCRT)

![image](https://user-images.githubusercontent.com/45724082/158000721-33c00c3e-68bb-4ee3-a2ae-aefa549cfb33.png)



