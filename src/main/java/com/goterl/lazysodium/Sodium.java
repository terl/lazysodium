/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.interfaces.*;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

public class Sodium {

    protected Sodium() {
    }

    protected void onRegistered() {
        if (sodium_init() == -1) {
            throw new IllegalStateException("Sodium library could not be initialised properly.");
        }
    }


    //// -------------------------------------------|
    //// HELPERS
    //// -------------------------------------------|


    public native int sodium_init();
    public native void sodium_increment(byte[] n, int nLen);
    public native void sodium_add(byte[] a, byte[] b, int len);
    public native int sodium_is_zero(byte[] n, int nLen);
    public native void sodium_stackzero(int len);
    public native int sodium_memcmp(byte[] b1, byte[] b2, int len);
    public native int sodium_base64_encoded_len(int binLen, int variant);
    public native int sodium_compare(byte[] b1, byte[] b2, int len);


    public native String sodium_bin2hex(byte[] hex, int hexMaxLen, byte[] bin, int binLen);

    public native int sodium_hex2bin(byte[] bin,
                                     int binMaxLen,
                                     byte[] hex,
                                     int hexLen,
                                     byte[] ignore,
                                     Pointer binLen,
                                     Pointer hexEnd);

    public native String sodium_bin2base64(byte[] b64,
                                          int b64MaxLen,
                                          byte[] bin,
                                          int binLen,
                                          int variant);

    public native int sodium_base642bin(byte[] bin,
                                        int binMaxLen,
                                        byte[] b64,
                                        int b64Len,
                                        byte[] ignore,
                                        Pointer binLen,
                                        Pointer b64End,
                                        int variant);




    //// -------------------------------------------|
    //// SECURE MEMORY
    //// -------------------------------------------|

    public native int sodium_memzero(byte[] pnt, int len);
    public native int sodium_mlock(byte[] addr, int len);
    public native int sodium_munlock(byte[] addr, int len);
    public native Pointer sodium_malloc(int size);
    public native Pointer sodium_allocarray(int count, int size);
    public native void sodium_free(Pointer p);
    public native int sodium_mprotect_noaccess(Pointer ptr);
    public native int sodium_mprotect_readonly(Pointer ptr);
    public native int sodium_mprotect_readwrite(Pointer ptr);





    //// -------------------------------------------|
    //// PADDING
    //// -------------------------------------------|

    public native int sodium_pad(Pointer paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize, int maxBufLen);

    public native int sodium_unpad(Pointer paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize);




    //// -------------------------------------------|
    //// RANDOM
    //// -------------------------------------------|

    public native long randombytes_random();

    public native long randombytes_uniform(int upperBound);

    public native void randombytes_buf(byte[] buffer, int size);

    public native void randombytes_buf_deterministic(byte[] buffer, int size, byte[] seed);





    //// -------------------------------------------|
    //// PASSWORD HASHING
    //// -------------------------------------------|

    public native int crypto_pwhash(byte[] outputHash,
                                 long outputHashLen,
                                 byte[] password,
                                 long passwordLen,
                                 byte[] salt,
                                 long opsLimit,
                                 NativeLong memLimit,
                                 int alg);

    public native int crypto_pwhash_str(byte[] outputStr,
                                     byte[] password,
                                     long passwordLen,
                                     long opsLimit,
                                     NativeLong memLimit);

    public native int crypto_pwhash_str_verify(byte[] hash, byte[] password, long passwordLen);

    public native int crypto_pwhash_str_needs_rehash(byte[] hash, long opsLimit, NativeLong memLimit);




    //// -------------------------------------------|
    //// HASHING
    //// -------------------------------------------|

    public native int crypto_hash_sha256(byte[] out, byte[] in, long inLen);

    public native int crypto_hash_sha512(byte[] out, byte[] in, long inLen);


    public native int crypto_hash_sha256_init(Hash.State256 state);

    public native int crypto_hash_sha256_update(Hash.State256 state,
                                                byte[] in,
                                                long inLen);

    public native int crypto_hash_sha256_final(Hash.State256 state, byte[] out);


    public native int crypto_hash_sha512_init(Hash.State512 state);

    public native int crypto_hash_sha512_update(Hash.State512 state,
                                                byte[] in,
                                                long inLen);

    public native int crypto_hash_sha512_final(Hash.State512 state, byte[] out);




    //// -------------------------------------------|
    //// KEY DERIVATION FUNCTIONS
    //// -------------------------------------------|

    public native void crypto_kdf_keygen(byte[] masterKey);

    public native int crypto_kdf_derive_from_key(byte[] subkey,
                                          int subkeyLen,
                                          long subkeyId,
                                          byte[] context,
                                          byte[] masterKey);





    //// -------------------------------------------|
    //// KEY EXCHANGE
    //// -------------------------------------------|

    public native int crypto_kx_keypair(byte[] publicKey, byte[] secretKey);

    public native int crypto_kx_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);

    public native int crypto_kx_client_session_keys(
            byte[] rx,
            byte[] tx,
            byte[] clientPk,
            byte[] clientSk,
            byte[] serverPk
    );

    public native int crypto_kx_server_session_keys(
            byte[] rx,
            byte[] tx,
            byte[] serverPk,
            byte[] serverSk,
            byte[] clientPk
    );






    //// -------------------------------------------|
    //// SECRET BOX
    //// -------------------------------------------|

    public native void crypto_secretbox_keygen(byte[] key);


    public native int crypto_secretbox_easy(byte[] cipherText,
                                     byte[] message,
                                     long messageLen,
                                     byte[] nonce,
                                     byte[] key);

    public native int crypto_secretbox_open_easy(byte[] message,
                                          byte[] cipherText,
                                          long cipherTextLen,
                                          byte[] nonce,
                                          byte[] key);

    public native int crypto_secretbox_detached(byte[] cipherText,
                                         byte[] mac,
                                         byte[] message,
                                         long messageLen,
                                         byte[] nonce,
                                         byte[] key);

    public native int crypto_secretbox_open_detached(byte[] message,
                                              byte[] cipherText,
                                              byte[] mac,
                                              long cipherTextLen,
                                              byte[] nonce,
                                              byte[] key);



    //// -------------------------------------------|
    //// CRYPTO BOX
    //// -------------------------------------------|

    public native int crypto_box_keypair(byte[] publicKey, byte[] secretKey);

    public native int crypto_box_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);


    public native int crypto_box_easy(
        byte[] cipherText,
        byte[] message,
        long messageLen,
        byte[] nonce,
        byte[] publicKey,
        byte[] secretKey
    );

    public native int crypto_box_open_easy(
            byte[] message,
            byte[] cipherText,
            long cipherTextLen,
            byte[] nonce,
            byte[] publicKey,
            byte[] secretKey
    );

    public native int crypto_box_detached(byte[] cipherText,
                                   byte[] mac,
                                   byte[] message,
                                   long messageLen,
                                   byte[] nonce,
                                   byte[] publicKey,
                                   byte[] secretKey);

    public native int crypto_box_open_detached(byte[] message,
                                        byte[] cipherText,
                                        byte[] mac,
                                        long cipherTextLen,
                                        byte[] nonce,
                                        byte[] publicKey,
                                        byte[] secretKey);

    public native int crypto_box_beforenm(byte[] k, byte[] publicKey, byte[] secretKey);


    public native int crypto_box_easy_afternm(
        byte[] cipherText,
        byte[] message,
        long messageLen,
        byte[] nonce,
        byte[] key
    );

    public native int crypto_box_open_easy_afternm(
            byte[] message, byte[] cipher,
            long cLen, byte[] nonce,
            byte[] key
    );

    public native int crypto_box_detached_afternm(
            byte[] cipherText,
            byte[] mac,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_box_open_detached_afternm(byte[] message,
                                        byte[] cipherText,
                                        byte[] mac,
                                        long cipherTextLen,
                                        byte[] nonce,
                                        byte[] key);


    public native int crypto_box_seal(byte[] cipher, byte[] message, long messageLen, byte[] publicKey);

    public native int crypto_box_seal_open(byte[] m,
                                    byte[] cipher,
                                    long cipherLen,
                                    byte[] publicKey,
                                    byte[] secretKey);




    //// -------------------------------------------|
    //// CRYPTO SIGN
    //// -------------------------------------------|

    public native int crypto_sign_init(Sign.StateCryptoSign state);

    public native int crypto_sign_update(Sign.StateCryptoSign state, byte[] chunk, long chunkLength);

    public native int crypto_sign_final_create(Sign.StateCryptoSign state, byte[] sig, Pointer sigLen, byte[] sk);

    public native int crypto_sign_final_verify(Sign.StateCryptoSign state, byte[] sig, byte[] pk);

    public native int crypto_sign_keypair(byte[] publicKey, byte[] secretKey);

    public native int crypto_sign_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);

    public native int crypto_sign(
            byte[] signedMessage,
            Pointer sigLength,
            byte[] message,
            long messageLen,
            byte[] secretKey
    );

    public native int crypto_sign_open(
            byte[] message,
            Pointer messageLen,
            byte[] signedMessage,
            long signedMessageLen,
            byte[] publicKey
    );


    public native int crypto_sign_detached(
            byte[] signature,
            Pointer sigLength,
            byte[] message,
            long messageLen,
            byte[] secretKey
    );

    public native int crypto_sign_verify_detached(byte[] signature, byte[] message, long messageLen, byte[] publicKey);


    public native int crypto_sign_ed25519_pk_to_curve25519(
            byte[] curve25519PublicKey,
            byte[] ed25519PublicKey
    );

    public native int crypto_sign_ed25519_sk_to_curve25519(
            byte[] curve25519SecretKey,
            byte[] ed25519SecretKey
    );

    public native int crypto_sign_ed25519_sk_to_seed(byte[] seed, byte[] ed25519SecretKey);

    public native int crypto_sign_ed25519_sk_to_pk(byte[] ed25519PublicKey, byte[] ed25519SecretKey);



    //// -------------------------------------------|
    //// SECRET STREAM
    //// -------------------------------------------|

    public native void crypto_secretstream_xchacha20poly1305_keygen(byte[] key);

    public native int crypto_secretstream_xchacha20poly1305_init_push(
            SecretStream.State state,
            byte[] header,
            byte[] key
    );

    public native int crypto_secretstream_xchacha20poly1305_push(
            SecretStream.State state,
            byte[] cipher,
            long[] cipherAddr,
            byte[] message,
            long messageLen,
            byte[] additionalData,
            long additionalDataLen,
            byte  tag
    );

    public native int crypto_secretstream_xchacha20poly1305_init_pull(
            SecretStream.State state,
            byte[] header,
            byte[] key
    );

    public native int crypto_secretstream_xchacha20poly1305_pull(
            SecretStream.State state,
            byte[] message,
            long[] messageAddress,
            byte[] tagAddress,
            byte[] cipher,
            long cipherLen,
            byte[] additionalData,
            long additionalDataLen
    );

    public native void crypto_secretstream_xchacha20poly1305_rekey(SecretStream.State state);

    public native int crypto_secretstream_xchacha20poly1305_abytes();
    public native int crypto_secretstream_xchacha20poly1305_headerbytes();
    public native int crypto_secretstream_xchacha20poly1305_keybytes();
    public native int crypto_secretstream_xchacha20poly1305_messagebytes_max();

    public native byte crypto_secretstream_xchacha20poly1305_tag_message();
    public native byte crypto_secretstream_xchacha20poly1305_tag_push();
    public native byte crypto_secretstream_xchacha20poly1305_tag_rekey();
    public native byte crypto_secretstream_xchacha20poly1305_tag_final();



    //// -------------------------------------------|
    //// STREAM
    //// -------------------------------------------|


    public native void crypto_stream_chacha20_keygen(byte[] key);

    public native int crypto_stream_chacha20(
            byte[] c,
            long cLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_chacha20_xor(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_chacha20_xor_ic(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            long ic,
            byte[] key
    );


    // IETF Chacha

    public native void crypto_stream_chacha20_ietf_keygen(byte[] key);

    public native int crypto_stream_chacha20_ietf(
            byte[] c,
            long cLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_chacha20_ietf_xor(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_chacha20_ietf_xor_ic(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            long ic,
            byte[] key
    );

    // Salsa20

    public native void crypto_stream_salsa20_keygen(byte[] key);

    public native int crypto_stream_salsa20(
            byte[] c,
            long cLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_salsa20_xor(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_salsa20_xor_ic(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            long ic,
            byte[] key
    );



    // XSalsa20

    public native void crypto_stream_keygen(byte[] key);

    public native int crypto_stream(
            byte[] c,
            long cLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_xor(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );





    //// -------------------------------------------|
    //// DIFFIE HELLMAN
    //// -------------------------------------------|

    public native int crypto_scalarmult_base(byte[] publicKey, byte[] secretKey);

    public native int crypto_scalarmult(byte[] shared, byte[] secretKey, byte[] publicKey);


    //// -------------------------------------------|
    //// CRYPTO AUTH
    //// -------------------------------------------|

    public native int crypto_auth(byte[] tag, byte[] in, long inLen, byte[] key);

    public native int crypto_auth_verify(byte[] tag, byte[] in, long inLen, byte[] key);

    public native void crypto_auth_keygen(byte[] k);


    public native void crypto_auth_hmacsha256_keygen(byte[] key);

    public native int crypto_auth_hmacsha256(
            byte[] out,
            byte[] in,
            long inLen,
            byte[] k
    );

    public native int crypto_auth_hmacsha256_verify(
            byte[] h,
            byte[] in,
            long inLen,
            byte[] k
    );

    public native int crypto_auth_hmacsha256_init(
            Auth.StateHMAC256 state,
            byte[] key,
            int keyLen
    );

    public native int crypto_auth_hmacsha256_update(
            Auth.StateHMAC256 state,
            byte[] in,
            long inLen
    );

    public native int crypto_auth_hmacsha256_final(
            Auth.StateHMAC256 state,
            byte[] out
    );



    public native void crypto_auth_hmacsha512256_keygen(byte[] key);

    public native int crypto_auth_hmacsha512256(
            byte[] out,
            byte[] in,
            long inLen,
            byte[] k
    );

    public native int crypto_auth_hmacsha512256_verify(
            byte[] h,
            byte[] in,
            long inLen,
            byte[] k
    );

    public native int crypto_auth_hmacsha512256_init(
            Auth.StateHMAC512256 state,
            byte[] key,
            int keyLen
    );

    public native int crypto_auth_hmacsha512256_update(
            Auth.StateHMAC512256 state,
            byte[] in,
            long inLen
    );

    public native int crypto_auth_hmacsha512256_final(
            Auth.StateHMAC512256 state,
            byte[] out
    );


    public native void crypto_auth_hmacsha512_keygen(byte[] key);

    public native int crypto_auth_hmacsha512(
            byte[] out,
            byte[] in,
            long inLen,
            byte[] k
    );

    public native int crypto_auth_hmacsha512_verify(
            byte[] h,
            byte[] in,
            long inLen,
            byte[] k
    );

    public native int crypto_auth_hmacsha512_init(
            Auth.StateHMAC512 state,
            byte[] key,
            int keyLen
    );

    public native int crypto_auth_hmacsha512_update(
            Auth.StateHMAC512 state,
            byte[] in,
            long inLen
    );

    public native int crypto_auth_hmacsha512_final(
            Auth.StateHMAC512 state,
            byte[] out
    );

    //// -------------------------------------------|
    //// SHORT HASH
    //// -------------------------------------------|

    public native int crypto_shorthash(byte[] out, byte[] in, long inLen, byte[] key);

    public native int crypto_shorthash_keygen(byte[] key);





    //// -------------------------------------------|
    //// GENERIC HASH
    //// -------------------------------------------|

    public native void crypto_generichash_keygen(byte[] k);

    public native int crypto_generichash(
            byte[] out, int outLen,
            byte[] in, long inLen,
            byte[] key, int keyLen
    );

    public native int crypto_generichash_init(byte[] state,
                                       byte[] key,
                                       int keyLength,
                                       int outLen);

    public native int crypto_generichash_update(byte[] state,
                                         byte[] in,
                                         long inLen);

    public native int crypto_generichash_final(byte[] state, byte[] out, int outLen);

    public native int crypto_generichash_statebytes();


    public native int crypto_generichash_blake2b_salt_personal(
            byte[] subKey,
            int subKeyLen,
            byte[] in,
            long inLen,
            byte[] masterKey,
            int masterKeyLen,
            byte[] subKeyId,
            byte[] context
    );

    public native int crypto_core_hchacha20(byte[] out,
                                            byte[] in,
                                            byte[] k,
                                            byte[] c);



    //// -------------------------------------------|
    //// AEAD
    //// -------------------------------------------|

    public native void crypto_aead_chacha20poly1305_keygen(byte[] key);

    public native int crypto_aead_chacha20poly1305_encrypt(
            byte[] c,
            long[] cLen,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    public native int crypto_aead_chacha20poly1305_decrypt(
            byte[] m,
            long[] mLen,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );

    public native int crypto_aead_chacha20poly1305_encrypt_detached(
            byte[] c,
            byte[] mac,
            long[] macLenAddress,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    public native int crypto_aead_chacha20poly1305_decrypt_detached(
            byte[] m,
            byte[] nsec,
            byte[] c,
            long cLen,
            byte[] mac,
            byte[] ad,
            long adLen,
            byte[] npub,
            byte[] k
    );

    // ietf

    public native void crypto_aead_chacha20poly1305_ietf_keygen(byte[] key);

    public native int crypto_aead_chacha20poly1305_ietf_encrypt(
            byte[] c,
            long[] cLen,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    public native int crypto_aead_chacha20poly1305_ietf_decrypt(
            byte[] m,
            long[] mLen,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );

    public native int crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            byte[] c,
            byte[] mac,
            long[] macLenAddress,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    public native int crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            byte[] m,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] mac,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );

    // xchacha

    public native void crypto_aead_xchacha20poly1305_ietf_keygen(byte[] k);

    public native int crypto_aead_xchacha20poly1305_ietf_encrypt(
            byte[] c,
            long[] cLen,
            byte[] m,
            long mLen,
            byte[] ad,
            long adLen,
            byte[] nSec,
            byte[] nPub,
            byte[] k
    );

    public native int crypto_aead_xchacha20poly1305_ietf_decrypt(
            byte[] m,
            long[] mLen,
            byte[] nSec,
            byte[] c,
            long cLen,
            byte[] ad,
            long adLen,
            byte[] nPub,
            byte[] k
    );


    public native int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            byte[] cipher,
            byte[] mac,
            long[] macLenAddress,
            byte[] message,
            long messageLen,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nSec,
            byte[] nPub,
            byte[] key
    );

    public native int crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            byte[] message,
            byte[] nSec,
            byte[] cipher,
            long cipherLen,
            byte[] mac,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nPub,
            byte[] key
    );


    // AES

    public native void crypto_aead_aes256gcm_keygen(byte[] key);

    public native int crypto_aead_aes256gcm_encrypt(
            byte[] cipher,
            long[] cipherLen,
            byte[] message,
            long messageLen,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nSec,
            byte[] nPub,
            byte[] key
    );

    public native int crypto_aead_aes256gcm_decrypt(
            byte[] message,
            long[] messageLen,
            byte[] nSec,
            byte[] cipher,
            long cipherLen,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nPub,
            byte[] key
    );

    public native int crypto_aead_aes256gcm_encrypt_detached(
        byte[] cipher,
        byte[] mac,
        long[] macLenAddress,
        byte[] message,
        long messageLen,
        byte[] additionalData,
        long additionalDataLen,
        byte[] nSec,
        byte[] nPub,
        byte[] key
    );

    public native int crypto_aead_aes256gcm_decrypt_detached(
            byte[] message,
            byte[] nSec,
            byte[] cipher,
            long cipherLen,
            byte[] mac,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nPub,
            byte[] key
    );



    public native int crypto_aead_aes256gcm_beforenm(
            AEAD.StateAES state,
            byte[] key
    );

    public native int crypto_aead_aes256gcm_encrypt_afternm(
            byte[] cipher,
            long[] cipherLength,
            byte[] message,
            long messageLen,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nSec,
            byte[] nPub,
            AEAD.StateAES state
    );

    public native int crypto_aead_aes256gcm_decrypt_afternm(
            byte[] message,
            long[] messageLength,
            byte[] nSec,
            byte[] cipher,
            long cipherLen,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nPub,
            AEAD.StateAES state
    );

    public native int crypto_aead_aes256gcm_encrypt_detached_afternm(
            byte[] cipher,
            byte[] mac,
            long[] macLenAddress,
            byte[] message,
            long messageLen,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nSec,
            byte[] nPub,
            AEAD.StateAES state
    );


    public native int crypto_aead_aes256gcm_decrypt_detached_afternm(
            byte[] message,
            byte[] nSec,
            byte[] cipher,
            long cipherLen,
            byte[] mac,
            byte[] additionalData,
            long additionalDataLen,
            byte[] nPub,
            AEAD.StateAES state
    );

    public native int crypto_aead_aes256gcm_is_available();


    // Ristretto255

    public native int crypto_core_ristretto255_is_valid_point(byte[] p);

    public native void crypto_core_ristretto255_random(byte[] p);

    public native int crypto_core_ristretto255_from_hash(byte[] p, byte[] r);

    public native int crypto_scalarmult_ristretto255(byte[] q, byte[] n, byte[] p);

    public native int crypto_scalarmult_ristretto255_base(byte[] q, byte[] n);

    public native int crypto_core_ristretto255_add(byte[] r, byte[] p, byte[] q);

    public native int crypto_core_ristretto255_sub(byte[] r, byte[] p, byte[] q);

    public native void crypto_core_ristretto255_scalar_random(byte[] r);

    public native void crypto_core_ristretto255_scalar_reduce(byte[] r, byte[] s);

    public native int crypto_core_ristretto255_scalar_invert(byte[] recip, byte[] s);

    public native void crypto_core_ristretto255_scalar_negate(byte[] neg, byte[] s);

    public native void crypto_core_ristretto255_scalar_complement(byte[] comp, byte[] s);

    public native void crypto_core_ristretto255_scalar_add(byte[] z, byte[] x, byte[] y);

    public native void crypto_core_ristretto255_scalar_sub(byte[] z, byte[] x, byte[] y);

    public native void crypto_core_ristretto255_scalar_mul(byte[] z, byte[] x, byte[] y);
}
