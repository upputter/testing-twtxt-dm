<?php

// AES encryption and decryption from https://stackoverflow.com/questions/68835102/how-to-convert-openssl-encrypt-and-decrypt-into-php

// https://docs.openssl.org/3.0/man7/EVP_KDF-PBKDF2/
// https://security.stackexchange.com/questions/31564/key-length-and-hash-function-in-pbkdf2
// https://stackoverflow.com/questions/58823814/what-default-parameters-uses-openssl-pbkdf2
// https://www.php.net/manual/en/function.openssl-pbkdf2.php
// https://github.com/meixler/web-browser-based-file-encryption-decryption/tree/master
// https://github.com/blocktrail/cryptojs-aes-php/blob/master/src/CryptoJSAES.php

class TwtxtDirectMessage
{
    public const CYPHER = 'aes-256-cbc';
    public const SALTSIZE = 8;
    public const ITERATIONS = 100000;
    public const PBKDF2_ALGO = 'sha256';

    protected $salt;
    protected $sharedKey;

    public function __construct(
        public string $publicKey,
        public string $privateKey,
        public bool $debug = false,
    ) {
        $this->publicKey = $this->getFullPemFromKeyString($this->publicKey, false);
        $this->privateKey = $this->getFullPemFromKeyString($this->privateKey, true);

        // generate shared key pair
        $this->sharedKey = openssl_pkey_derive($this->publicKey, $this->privateKey);
        $this->debug('Shared Key (B64): ' . base64_encode($this->sharedKey));
    }

    protected function debug($info)
    {
        if ($this->debug) {
            echo $info . '<br />' . PHP_EOL;
        }
    }

    public function encrypt($message)
    {
        $this->debug('** ENCRYPT **');
        $this->debug('Plain Message: ' . $message);

        $this->salt = openssl_random_pseudo_bytes(self::SALTSIZE);
        $this->debug('Generated Salt (B64): ' . base64_encode($this->salt));

        $pbkdf2key = $this->generatEPBKDF2key($this->sharedKey);
        $this->debug('PBKDF2 KEY (B64): ' . base64_encode($pbkdf2key));

        $encryptedMessage = $this->aesEncryption($pbkdf2key, $message);
        $this->debug('Encrypted Message: <pre>' . $encryptedMessage . '</pre>');

        return base64_decode($encryptedMessage);
    }

    public function decrypt($encryptedMessage)
    {
        $this->debug('** DECRYPT **');
        $this->debug('Encrypted Message: <pre>' . $encryptedMessage . '</pre>');

        $decodedData = $this->decode($encryptedMessage);
        $this->salt = $decodedData['salt'];
        $this->debug('Decoded Salt (B64): ' . base64_encode($this->salt) . ' (' . strlen($this->salt) . ')');

        $pbkdf2key = $this->generatEPBKDF2key($this->sharedKey);
        $this->debug('PBKDF2 KEY (B64): ' . base64_encode($pbkdf2key));

        $decryptedMessage = $this->aesDecryption($pbkdf2key, $encryptedMessage);
        $this->debug('Decrypted Message: ' . $decryptedMessage);

        return $decryptedMessage;
    }

    protected function aesEncryption($passphrase, $data)
    {
        list($key, $iv) = $this->evpkdf($passphrase, $this->salt);
        $encryptedData = openssl_encrypt(
            $data,
            self::CYPHER,
            $key,
            true,
            $iv
        );
        return $this->encode($encryptedData, $this->salt);
    }

    protected function aesDecryption($passphrase, $encData)
    {
        if ($this->is_base64($encData)) {
            $this->debug('B64-decode encrypted data.');
            $encData = base64_decode($encData);
        }

        $decodedData = $this->decode($encData);
        list($key, $iv) = $this->evpkdf($passphrase, $this->salt);

        $this->debug('iv (B64): ' . base64_encode($iv) . ' (' . strlen($iv) .')');

        $data = openssl_decrypt(
            $decodedData['data'],
            self::CYPHER,
            $key,
            true,
            $iv
        );
        return $data;
    }

    // add 'Salted__' string and salt to content
    protected function encode($ct, $salt)
    {
        return base64_encode('Salted__' . $salt . $ct);
    }

    protected function decode($data)
    {
        // the string "Salted__" is 8 bytes long
        if (substr($data, 0, 8) !== 'Salted__') {
            $this->debug('Error: Unsalted Data');
            return false;
        }
        // get the salt after the "Salted__" string wit the given salt size
        $salt = substr($data, 8, self::SALTSIZE);

        // get the encrypted content after the salt ends
        $content = substr($data, 8 + self::SALTSIZE);
        return [
            'data' => $content,
            'salt' => $salt
        ];
    }

    protected function evpkdf($passphrase, $salt)
    {
        $salted = '';
        $dx = '';
        while (strlen($salted) < 48) {
            $dx = md5($dx . $passphrase . $salt, true);
            $salted .= $dx;
        }
        $key = substr($salted, 0, 32);
        // iv for aes-256-cbc must be 16 bytes long
        $iv = substr($salted, 32, 16);
        return [$key, $iv];
    }

    protected function generatEPBKDF2key($key)
    {
        $generated_key = openssl_pbkdf2(
            $key, // the shared key
            $this->salt,
            strlen($key), // length of the shared key
            self::ITERATIONS,
            self::PBKDF2_ALGO
        );

        return $generated_key;
    }

    // openssl_pkey_derive() needs the full PEM key structure
    protected function getFullPemFromKeyString($key, $isPrivate = false)
    {
        $keyType = ($isPrivate) ? 'PRIVATE' : 'PUBLIC';
        return '-----BEGIN ' . $keyType . ' KEY-----' . PHP_EOL . $key . PHP_EOL . '-----END ' . $keyType . ' KEY-----' .PHP_EOL;
    }

    protected function is_base64($s)
    {
        return (bool) preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $s);
    }
}
