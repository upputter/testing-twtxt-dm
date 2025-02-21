# Testing Twtxt Direct Messages
The [Direct Message Extension](https://twtxt.dev/exts/direct-message.html) uses OpenSSL to encrypt and decrypt messages for Twtxt.

This is an implementation of the Twtxt Direct Message Extansion in PHP. Everything needed is within the `crypt.class.php`.

## Important
DO NOT USE THE KEYS FROM THIS REPOSITORY IN PRODUCTION!

## Requirements
You need your own public and private keypair and a remote public key.

Your keys can be generated with OpenSSL and the Curve25519 algorithm.

Generate your **private** key:

```shell
openssl genpkey -algorithm X25519 -out YOUR_PRIVATE_KEY.pem
```

Generate your **public** key from your private key:

```shell
openssl pkey -pubout -in YOUR_PRIVATE_KEY.pem -out YOUR_PUBLIC_KEY.pem
```

## Usage
To use the functionality, you only need the plain key form your key PEM-files (without header `-----BEGIN PRIVATE/PUBLIC KEY-----` or footer `-----END PRIVATE/PUBLIC KEY-----`

### Encryption
To encrypt a message with a remote public key and your private key use:

```php
$remotePublicKey = 'MCowBQYDK2VuAyEAeb5+mCYPNnClhk+O9aAJTF2n0Nc0V6aJuXjTkvJDR20=';
$yourPrivateKey = 'MC4CAQAwBQYDK2VuBCIEIHi6m5cQYspG+yT1xP3/d1k8IsOKlWVhIN5VzSVI5I1u';

// initialize the encryptor with the needed keys
$encryptor = new TwtxtDirectMessage(
        $remotePublicKey,
        $yourPrivateKey
);
// get the binary encrypt the message
$binaryEncryptedMessage = $encryptor->encrypt('YOUR SECRET MESSAGE GOES HERE');

// base64 encode the binary encrypted message
$base64EncryptedMessage = base64_encode($binaryEncryptedMessage);
```

### Decryption
To decrypt a message with your private key and a remote public key use:

```php
// get the raw binary encrypted message
$rawEncryptedMessage = base64_decode($THE_BASE64_ENCODED_CRYPTED_MESSAGE);

// initialize the encryptor with the needed keys
$decryptor = new TwtxtDirectMessage(
        $remotePublicKey,
        $yourPrivateKey
);
// get the plaintext decrypted message
$plaintextDecryptedMessage = $decryptor->decrypt($rawEncryptedMessage);
```

## Information
To implement the OpenSSL behavior in PHP one need to know some standard or default parameters of then OpenSSL `enc` application.

 * salt length: 8
 * desired PBKDF2 key size: 48
 * used PBKDF2 algorithm: sha256

### Encryption

The OpenSSL command for encryption used in the Twtxt Direct Message Extension is:

```shell
openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -out message.enc -pass file:shared_key.bin
```

The used salt length is **8** bytes. In the encryption process it's a random value.

The OpenSSL `enc` application uses the given shared key (reomte public key and your private key combined) and the "salt" together with the "**sha256**" algorithm, to create a password with PBKDF2 for the encryption. It iterates 100.000 times. Let's name it "PBKDF2KEY". This key is **48** bytes long.

Then OpenSSL generates the initialization vector (IV) from the last **16** bytes of the PBKDF2KEY.

The encrypted message is generated using AES-256-CBC, the generated PBKDF2KEY, the given salt and the IV from the generated PBKDF2KEY.

The final full encrypted message consist of a fixed string `Salted__`, folled by the given salt and the encrypted message.

### Decryption

The OpenSSL command for decryption used in the Twtxt Direct Message Extension is:
```shell
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in encryptedMessage.enc -out plaintextMessage.txt -pass file:shared_key.bin
```

The first **8** bytes of the full encrypted data are the magic numbers "Salted__", followed by the **8** bytes long "salt" and the encrypted message itself.

The shared key is used to generate the PBKDF2KEY, using the salt from the encrypted message, like in the encryption proccess.

To decrypt the encrypted message, the same values from the encryption are needed: PBKDF2KEY, the salt and the IV from the PBKDF2KEY.