<?php
 $options = ['size' => 2048, 'passphrase' => null,'algo' => 'sha512'];
     
 // @see https://www.php.net/manual/en/function.openssl-csr-new.php
 $resource = openssl_pkey_new([
     'private_key_bits' => (int) $options['size'],
     'private_key_type' => OPENSSL_KEYTYPE_RSA,
     'digest_alg' => $options['algo'],
     'encrypt_key' => $options['passphrase'] !== null
 ]);
 openssl_pkey_export($resource, $privateKey);
 print_r($privateKey);;

 $keyDetails = openssl_pkey_get_details(openssl_pkey_get_private($privateKey));

 print_r($keyDetails['key']);
