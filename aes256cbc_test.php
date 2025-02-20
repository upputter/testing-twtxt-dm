<?php

    require_once('./crypt.class.php');

    /* openssl generated keys

    openssl genpkey -algorithm X25519 -out alice_private_key.pem
    openssl pkey -pubout -in alice_private_key.pem -out alice_public_key.pem

    openssl genpkey -algorithm X25519 -out bob_private_key.pem
    openssl pkey -pubout -in bob_private_key.pem -out bob_public_key.pem

    */

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

    $message = 'Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna';

    $debug = true;

    // bob encrypts a message for alice
    $encryptor = new TwtxtDirectMessage(
        $keys['alice']['pub'],
        $keys['bob']['priv'],
        $debug
    );

    $message_encrypted = $encryptor->encrypt($message);

    $filename = './messages/encryption_test_' . date('Ymdhis') . 'enc';

    file_put_contents($filename, $message_encrypted);

    echo '<hr />';

    // alice decrypts the message from bob
    $decryptor = new TwtxtDirectMessage(
        $keys['bob']['pub'],
        $keys['alice']['priv'],
        $debug
    );

    $decrypted_message = $decryptor->decrypt(file_get_contents($filename));
