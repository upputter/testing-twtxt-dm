<?php

$keys = [
    'alice' => [
        'pub' => 'MCowBQYDK2VuAyEAeb5+mCYPNnClhk+O9aAJTF2n0Nc0V6aJuXjTkvJDR20=',
        'priv' => 'MC4CAQAwBQYDK2VuBCIEIJDajjYeyhhlrQTJtWo5EOo5RcN6KjcD6iWVn9sIKJdu',
    ],
    'bob' => [
        'pub' => 'MCowBQYDK2VuAyEAjQjyVVlX4yLx7IE/sTN9ccpuq484vfJ8Kw9eqM350TY=',
        'priv' => 'MC4CAQAwBQYDK2VuBCIEIHi6m5cQYspG+yT1xP3/d1k8IsOKlWVhIN5VzSVI5I1u',
    ]

];

$message = 'Hallo Welt. Heute ist ein schöner Tag!';

echo 'plain message: ' . $message . '<br />';

$key_alice = sodium_crypto_box_keypair_from_secretkey_and_publickey(
    substr(base64_decode($keys['alice']['priv']), -32),
    sodium_crypto_box_publickey_from_secretkey(substr(base64_decode($keys['alice']['priv']), -32))
    // substr(base64_decode($keys['alice']['pub']), -32)
);

$key_bob = sodium_crypto_box_keypair_from_secretkey_and_publickey(
    substr(base64_decode($keys['bob']['priv']), -32),
    substr(base64_decode($keys['bob']['pub']), -32)
);



echo '<br >';
// encrypt

// $alice_pubkey = substr(base64_decode($keys['alice']['pub']), -32);
// $key_bob_priv = substr(base64_decode($keys['bob']['priv']), -32);

// $shared_key_enc = sodium_crypto_scalarmult(sodium_crypto_box_secretkey($key_bob), sodium_crypto_box_publickey($key_alice));
$encryption_key = sodium_crypto_box_keypair_from_secretkey_and_publickey(
    sodium_crypto_box_secretkey($key_bob),
    sodium_crypto_box_publickey($key_alice)
);

echo '<br />'.base64_encode($encryption_key) .'<br />';
;

$nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

$encrypted_message = base64_encode(sodium_crypto_box($message, $nonce, $encryption_key));

echo 'Encrypted Message: ' . $encrypted_message .'<br />';

// decrypt


$decryption_key = sodium_crypto_box_keypair_from_secretkey_and_publickey(
    sodium_crypto_box_secretkey($key_alice),
    sodium_crypto_box_publickey($key_bob)
);

$nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

$decrypted_message = sodium_crypto_box_open(base64_decode($encrypted_message), $nonce, $decryption_key);
echo 'Decrypt Message: ' . $decrypted_message . '<br />';
