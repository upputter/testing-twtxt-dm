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

    // the file ./messages/00_well_known_message.enc was encrypted with the parameter "-p"

    /* the bin2hex datas for encryption parameter are:

        salt=4DBF688F4ED48705
        key=308234CA3F8C0B4987371DB9E15A1AAFCD1B8BD3FB8E6A1CB34FB1FA29DAC411
        iv =97F3EF9038CE28C1597BBDCAA6DAEF5B

    */

    $wellknown = [
        'salt' => hex2bin('4DBF688F4ED48705'),
        'key' => hex2bin('308234CA3F8C0B4987371DB9E15A1AAFCD1B8BD3FB8E6A1CB34FB1FA29DAC411'),
        'iv' => hex2bin('97F3EF9038CE28C1597BBDCAA6DAEF5B')
    ];

    echo 'Known salt (B64): ' . base64_encode($wellknown['salt']) . ' (' . strlen($wellknown['salt']). ')<br />';
    echo 'Known key (B64): ' . base64_encode($wellknown['key']) . '<br />';
    echo 'Known iv (B64): ' . base64_encode($wellknown['iv']) . ' (' . strlen($wellknown['iv']) . ')<br />';

    echo '<hr />';

    $filename = './messages/00_well_known_message.enc';

    $debug = true;

    // decrypt the well known message
    $decryptor = new TwtxtDirectMessage(
        $keys['bob']['pub'],
        $keys['alice']['priv'],
        $debug
    );

    $decrypted_message = $decryptor->decrypt(file_get_contents($filename));
