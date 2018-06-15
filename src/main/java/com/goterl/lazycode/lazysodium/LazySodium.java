/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.*;
import com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
import com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazycode.lazysodium.utils.KeyPair;
import com.goterl.lazycode.lazysodium.utils.SessionPair;
import com.sun.jna.Pointer;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public abstract class LazySodium implements
        Base,
        Random,
        AEAD.Native, AEAD.Lazy,
        GenericHash.Native, GenericHash.Lazy,
        ShortHash.Native, ShortHash.Lazy,
        SecureMemory.Native, SecureMemory.Lazy,
        Auth.Native, Auth.Lazy,
        SecretStream.Native, SecretStream.Lazy,
        Padding.Native, Padding.Lazy,
        Helpers.Native, Helpers.Lazy,
        PwHash.Native, PwHash.Lazy,
        Hash.Native, Hash.Lazy,
        Sign.Native, Sign.Lazy,
        Box.Native, Box.Lazy,
        SecretBox.Native, SecretBox.Lazy,
        KeyExchange.Native, KeyExchange.Lazy,
        KeyDerivation.Native, KeyDerivation.Lazy  {

    protected Charset charset = Charset.forName("UTF-8");


    public LazySodium() {
    }

    public LazySodium(Charset charset) {
        this.charset = charset;
    }


    public static Integer longToInt(long lng) {
        if (lng > Integer.MAX_VALUE) {
            return Integer.MAX_VALUE - 200;
        }
        if (lng < 0) {
            return 0;
        }

        return (int) lng;
    }



    //// -------------------------------------------|
    //// HELPERS
    //// -------------------------------------------|

    @Override
    public int sodiumInit() {
        return getSodium().sodium_init();
    }

    @Override
    public String sodiumBin2Hex(byte[] bin) {
        return bytesToHex(bin);
    }

    @Override
    public byte[] sodiumHex2Bin(String hex) {
        return hexToBytes(hex);
    }

    /**
     * Bytes to hexadecimal. Equivalent to {@link #sodiumBin2Hex(byte[])} but static.
     * @param bin Byte array.
     * @return Hexadecimal string.
     */
    public static String toHex(byte[] bin) {
        return bytesToHex(bin);
    }


    /**
     * Hexadecimal string to bytes. Equivalent to {@link #sodiumHex2Bin(String)}} but static.
     * @param hex Hexadecimal string to convert to bytes.
     * @return Byte array.
     */
    public static byte[] toBin(String hex) {
        return hexToBytes(hex);
    }


    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    // The following is from https://stackoverflow.com/a/9855338/3526705
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    // The following is from https://stackoverflow.com/a/140861/3526705
    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }



    //// -------------------------------------------|
    //// RANDOM
    //// -------------------------------------------|

    @Override
    public byte randomBytesRandom() {
        return getSodium().randombytes_random();
    }

    @Override
    public byte[] randomBytesBuf(int size) {
        byte[] bs = new byte[size];
        getSodium().randombytes_buf(bs, size);
        return bs;
    }

    @Override
    public byte[] nonce(int size) {
        return randomBytesBuf(size);
    }

    @Override
    public byte randomBytesUniform(int upperBound) {
        return getSodium().randombytes_uniform(upperBound);
    }

    @Override
    public byte[] randomBytesDeterministic(int size, byte[] seed) {
        byte[] bs = new byte[size];
        getSodium().randombytes_buf_deterministic(bs, size, seed);
        return bs;
    }



    //// -------------------------------------------|
    //// PADDING
    //// -------------------------------------------|

    @Override
    public boolean sodiumPad(int paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize, int maxBufLen) {
        return successful(getSodium().sodium_pad(paddedBuffLen, buf, unpaddedBufLen, blockSize, maxBufLen));
    }

    @Override
    public boolean sodiumUnpad(int unPaddedBuffLen, char[] buf, int paddedBufLen, int blockSize) {
        return successful(getSodium().sodium_unpad(unPaddedBuffLen, buf, paddedBufLen, blockSize));
    }



    //// -------------------------------------------|
    //// SECURE MEMORY
    //// -------------------------------------------|

    @Override
    public boolean sodiumMemZero(byte[] pnt, int len) {
        return successful(getSodium().sodium_memzero(pnt, len));
    }

    @Override
    public boolean sodiumMLock(byte[] array, int len) {
        return successful(getSodium().sodium_mlock(array, len));
    }

    @Override
    public boolean sodiumMUnlock(byte[] array, int len) {
        return successful(getSodium().sodium_munlock(array, len));
    }

    @Override
    public Pointer sodiumMalloc(int size) {
        return getSodium().sodium_malloc(size);
    }

    @Override
    public Pointer sodiumAllocArray(int count, int size) {
        return getSodium().sodium_allocarray(count, size);
    }

    @Override
    public void sodiumFree(Pointer p) {
        getSodium().sodium_free(p);
    }

    @Override
    public boolean sodiumMProtectNoAccess(Pointer ptr) {
        return successful(getSodium().sodium_mprotect_noaccess(ptr));
    }

    @Override
    public boolean sodiumMProtectReadOnly(Pointer ptr) {
        return successful(getSodium().sodium_mprotect_readonly(ptr));
    }

    @Override
    public boolean sodiumMProtectReadWrite(Pointer ptr) {
        return successful(getSodium().sodium_mprotect_readwrite(ptr));
    }



    //// -------------------------------------------|
    //// KDF KEYGEN
    //// -------------------------------------------|

    @Override
    public void cryptoKdfKeygen(byte[] masterKey) {
        getSodium().crypto_kdf_keygen(masterKey);
    }

    @Override
    public String cryptoKdfKeygen(Charset charset) {
        byte[] masterKeyInBytes = new byte[KeyDerivation.MASTER_KEY_BYTES];
        getSodium().crypto_kdf_keygen(masterKeyInBytes);
        return sodiumBin2Hex(masterKeyInBytes);
    }

    @Override
    public String cryptoKdfKeygen() {
        byte[] masterKey = new byte[KeyDerivation.MASTER_KEY_BYTES];
        getSodium().crypto_kdf_keygen(masterKey);
        return sodiumBin2Hex(masterKey);
    }

    @Override
    public String cryptoKdfDeriveFromKey(int lengthOfSubkey, long subKeyId, String context, byte[] masterKey)
            throws SodiumException {
        return cryptoKdfDeriveFromKey(lengthOfSubkey, subKeyId, context, sodiumBin2Hex(masterKey));
    }

    @Override
    public String cryptoKdfDeriveFromKey(int lengthOfSubkey, long subKeyId, String context, String masterKey)
            throws SodiumException {
        if (!KeyDerivation.Checker.subKeyIsCorrect(lengthOfSubkey)) {
            throw new SodiumException("Subkey is not between the correct lengths.");
        }
        if (!KeyDerivation.Checker.masterKeyIsCorrect(sodiumHex2Bin(masterKey).length)) {
            throw new SodiumException("Master key is not the correct length.");
        }
        if (!KeyDerivation.Checker.contextIsCorrect(bytes(context).length)) {
            throw new SodiumException("Context is not the correct length.");
        }
        byte[] subKey = new byte[lengthOfSubkey];
        byte[] contextAsBytes = bytes(context);
        byte[] masterKeyAsBytes = sodiumHex2Bin(masterKey);
        int res = getSodium().crypto_kdf_derive_from_key(
                subKey,
                lengthOfSubkey,
                subKeyId,
                contextAsBytes,
                masterKeyAsBytes
        );
        return res(res, sodiumBin2Hex(subKey));
    }

    @Override
    public int cryptoKdfDeriveFromKey(byte[] subKey, int subKeyLen, long subKeyId, byte[] context, byte[] masterKey) {
        return getSodium().crypto_kdf_derive_from_key(subKey, subKeyLen, subKeyId, context, masterKey);
    }



    //// -------------------------------------------|
    //// KEY EXCHANGE
    //// -------------------------------------------|

    @Override
    public boolean cryptoKxKeypair(byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_kx_keypair(publicKey, secretKey));
    }

    @Override
    public boolean cryptoKxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        return successful(getSodium().crypto_kx_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoKxClientSessionKeys(byte[] rx, byte[] tx, byte[] clientPk, byte[] clientSk, byte[] serverPk) {
        return successful(getSodium().crypto_kx_client_session_keys(rx, tx, clientPk, clientSk, serverPk));
    }

    @Override
    public boolean cryptoKxServerSessionKeys(byte[] rx, byte[] tx, byte[] serverPk, byte[] serverSk, byte[] clientPk) {
        return successful(getSodium().crypto_kx_server_session_keys(rx, tx, serverPk, serverSk, clientPk));
    }


    // -- Lazy functions

    @Override
    public KeyPair cryptoKxKeypair() {
        byte[] secretKey = randomBytesBuf(KeyExchange.SECRETKEYBYTES);
        byte[] publicKey = randomBytesBuf(KeyExchange.PUBLICKEYBYTES);

        getSodium().crypto_kx_keypair(publicKey, secretKey);

        return new KeyPair(toHex(publicKey), toHex(secretKey));
    }

    @Override
    public KeyPair cryptoKxKeypair(byte[] seed) {
        byte[] secretKey = randomBytesBuf(KeyExchange.SECRETKEYBYTES);
        byte[] publicKey = randomBytesBuf(KeyExchange.PUBLICKEYBYTES);

        getSodium().crypto_kx_seed_keypair(publicKey, secretKey, seed);

        return new KeyPair(toHex(publicKey), toHex(secretKey));
    }

    @Override
    public SessionPair cryptoKxClientSessionKeys(byte[] clientPk, byte[] clientSk, byte[] serverPk) throws SodiumException {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];

        if (!cryptoKxClientSessionKeys(rx, tx, clientPk, clientSk, serverPk)) {
            throw new SodiumException("Failure in creating client session keys.");
        }

        return new SessionPair(rx, tx);
    }

    @Override
    public SessionPair cryptoKxClientSessionKeys(KeyPair clientKeyPair, KeyPair serverKeyPair) throws SodiumException {
        return cryptoKxClientSessionKeys(clientKeyPair.getPublicKey(), clientKeyPair.getSecretKey(), serverKeyPair.getPublicKey());
    }

    @Override
    public SessionPair cryptoKxServerSessionKeys(byte[] serverPk, byte[] serverSk, byte[] clientPk) throws SodiumException {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];

        if (!cryptoKxServerSessionKeys(rx, tx, serverPk,  serverSk, clientPk)) {
            throw new SodiumException("Failure in creating server session keys.");
        }

        return new SessionPair(rx, tx);
    }

    @Override
    public SessionPair cryptoKxServerSessionKeys(KeyPair serverKeyPair, KeyPair clientKeyPair) throws SodiumException {
        return cryptoKxServerSessionKeys(serverKeyPair.getPublicKey(), serverKeyPair.getSecretKey(), clientKeyPair.getPublicKey());
    }


    //// -------------------------------------------|
    //// PASSWORD HASHING
    //// -------------------------------------------|

    @Override
    public boolean cryptoPwHash(byte[] outputHash,
                                long outputHashLen,
                                byte[] password,
                                long passwordLen,
                                byte[] salt,
                                long opsLimit,
                                long memLimit,
                                PwHash.Alg alg) {
        int res = getSodium().crypto_pwhash(outputHash,
                outputHashLen,
                password,
                passwordLen,
                salt,
                opsLimit,
                memLimit,
                alg.getValue());
        return successful(res);
    }

    @Override
    public boolean cryptoPwHashStr(byte[] outputStr,
                                   byte[] password,
                                   long passwordLen,
                                   long opsLimit,
                                   long memLimit) {
        int res = getSodium().crypto_pwhash_str(outputStr, password, passwordLen, opsLimit, memLimit);
        return successful(res);
    }

    @Override
    public boolean cryptoPwHashStrVerify(byte[] hash, byte[] password, long passwordLen) {
        return successful(getSodium().crypto_pwhash_str_verify(hash, password, passwordLen));
    }

    @Override
    public boolean cryptoPwHashStrNeedsRehash(byte[] hash, long opsLimit, long memLimit) {
        return successful(getSodium().crypto_pwhash_str_needs_rehash(hash, opsLimit, memLimit));
    }


    // lazy


    @Override
    public String cryptoPwHash(String password, long lengthOfHash, byte[] salt, long opsLimit, long memLimit, PwHash.Alg alg)
            throws SodiumException {
        byte[] passwordBytes = bytes(password);
        PwHash.Checker.checkAll(passwordBytes.length, salt.length, opsLimit, memLimit);
        byte[] hash = new byte[longToInt(lengthOfHash)];
        cryptoPwHash(hash, hash.length, passwordBytes, passwordBytes.length, salt, opsLimit, memLimit, alg);
        return toHex(hash);
    }

    @Override
    public String cryptoPwHashStr(String password, long opsLimit, long memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }
        return toHex(hash);
    }

    @Override
    public String cryptoPwHashStrRemoveNulls(String password, long opsLimit, long memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }

        byte[] hashNoNulls = removeNulls(hash);
        return toHex(hashNoNulls);
    }

    @Override
    public boolean cryptoPwHashStrVerify(String hash, String password) {
        byte[] hashBytes = toBin(hash);
        byte[] passwordBytes = bytes(password);

        // If the end of the hash does not have an null byte,
        // let's add it.
        byte endOfHash = hashBytes[hashBytes.length - 1];

        if (endOfHash != 0) {
            byte[] hashWithNullByte = new byte[hashBytes.length + 1];
            System.arraycopy(hashBytes, 0, hashWithNullByte, 0, hashBytes.length);
            hashBytes = hashWithNullByte;
        }


        return cryptoPwHashStrVerify(hashBytes, passwordBytes, passwordBytes.length);
    }



    //// -------------------------------------------|
    //// HASH
    //// -------------------------------------------|


    @Override
    public boolean cryptoHashSha256(byte[] out, byte[] in, long inLen) {
        return successful(getSodium().crypto_hash_sha256(out, in, inLen));
    }

    @Override
    public boolean cryptoHashSha256Init(Hash.State256 state) {
        return successful(getSodium().crypto_hash_sha256_init(state));
    }

    @Override
    public boolean cryptoHashSha256Update(Hash.State256 state, byte[] in, long inLen) {
        return successful(getSodium().crypto_hash_sha256_update(state, in, inLen));
    }

    @Override
    public boolean cryptoHashSha256Final(Hash.State256 state, byte[] out) {
        return successful(getSodium().crypto_hash_sha256_final(state, out));
    }

    @Override
    public boolean cryptoHashSha512(byte[] out, byte[] in, long inLen) {
        return successful(getSodium().crypto_hash_sha512(out, in, inLen));
    }

    @Override
    public boolean cryptoHashSha512Init(Hash.State512 state) {
        return successful(getSodium().crypto_hash_sha512_init(state));
    }

    @Override
    public boolean cryptoHashSha512Update(Hash.State512 state, byte[] in, long inLen) {
        return successful(getSodium().crypto_hash_sha512_update(state, in, inLen));
    }

    @Override
    public boolean cryptoHashSha512Final(Hash.State512 state, byte[] out) {
        return successful(getSodium().crypto_hash_sha512_final(state, out));
    }

    // -- lazy


    @Override
    public String cryptoHashSha256(String message) throws SodiumException {
        byte[] msgBytes = bytes(message);
        byte[] hashedBytes = new byte[Hash.SHA256_BYTES];
        if (!cryptoHashSha256(hashedBytes, msgBytes, msgBytes.length)) {
            throw new SodiumException("Unsuccessful sha-256 hash.");
        }
        return toHex(hashedBytes);
    }

    @Override
    public String cryptoHashSha512(String message) throws SodiumException {
        byte[] msgBytes = bytes(message);
        byte[] hashedBytes = new byte[Hash.SHA512_BYTES];
        if (!cryptoHashSha512(hashedBytes, msgBytes, msgBytes.length)) {
            throw new SodiumException("Unsuccessful sha-512 hash.");
        }
        return toHex(hashedBytes);
    }


    @Override
    public boolean cryptoHashSha256Update(Hash.State256 state, String messagePart) {
        byte[] msgBytes = bytes(messagePart);
        return cryptoHashSha256Update(state, msgBytes, msgBytes.length);
    }

    @Override
    public String cryptoHashSha256Final(Hash.State256 state) throws SodiumException {
        byte[] finalHash = new byte[Hash.SHA256_BYTES];
        if (!cryptoHashSha256Final(state, finalHash)) {
            throw new SodiumException("Could not finalise sha-256.");
        }
        return toHex(finalHash);
    }


    @Override
    public boolean cryptoHashSha512Update(Hash.State512 state, String messagePart) {
        byte[] msgBytes = bytes(messagePart);
        return cryptoHashSha512Update(state, msgBytes, msgBytes.length);
    }

    @Override
    public String cryptoHashSha512Final(Hash.State512 state) throws SodiumException {
        byte[] finalHash = new byte[Hash.SHA512_BYTES];
        if (!cryptoHashSha512Final(state, finalHash)) {
            throw new SodiumException("Could not finalise sha-512.");
        }
        return toHex(finalHash);
    }





    //// -------------------------------------------|
    //// SECRET BOX
    //// -------------------------------------------|

    @Override
    public void cryptoSecretBoxKeygen(byte[] key) {
        getSodium().crypto_secretbox_keygen(key);
    }

    @Override
    public boolean cryptoSecretBoxEasy(byte[] cipherText, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_secretbox_easy(cipherText, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxOpenEasy(byte[] message, byte[] cipherText, long cipherTextLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_secretbox_open_easy(message, cipherText, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxDetached(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_secretbox_detached(cipherText, mac, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxOpenDetached(byte[] message, byte[] cipherText, byte[] mac, long cipherTextLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_secretbox_open_detached(message, cipherText, mac, cipherTextLen, nonce, key));
    }


    /// --- Lazy

    @Override
    public String cryptoSecretBoxKeygen() {
        byte[] key = new byte[SecretBox.KEYBYTES];
        cryptoSecretBoxKeygen(key);
        return toHex(key);
    }

    @Override
    public String cryptoSecretBoxEasy(String message, byte[] nonce, String key) throws SodiumException {
        byte[] keyBytes = toBin(key);
        byte[] messageBytes = bytes(message);
        byte[] cipherTextBytes = new byte[SecretBox.MACBYTES + messageBytes.length];

        if (!cryptoSecretBoxEasy(cipherTextBytes, messageBytes, messageBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not encrypt message.");
        }

        return toHex(cipherTextBytes);
    }

    @Override
    public String cryptoSecretBoxOpenEasy(String cipher, byte[] nonce, String key) throws SodiumException {
        byte[] keyBytes = toBin(key);
        byte[] cipherBytes = toBin(cipher);
        byte[] messageBytes = new byte[cipherBytes.length - SecretBox.MACBYTES];


        if (!cryptoSecretBoxOpenEasy(messageBytes, cipherBytes, cipherBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not decrypt message.");
        }

        return str(messageBytes);
    }

    @Override
    public DetachedEncrypt cryptoSecretBoxDetached(String message, byte[] nonce, String key) throws SodiumException {
        byte[] keyBytes = toBin(key);
        byte[] messageBytes = bytes(message);
        byte[] cipherTextBytes = new byte[messageBytes.length];
        byte[] macBytes = new byte[SecretBox.MACBYTES];

        if (!cryptoSecretBoxDetached(cipherTextBytes, macBytes, messageBytes, messageBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not encrypt detached message.");
        }

        return new DetachedEncrypt(cipherTextBytes, macBytes);
    }

    @Override
    public String cryptoSecretBoxOpenDetached(DetachedEncrypt cipherAndMac, byte[] nonce, String key) throws SodiumException {
        byte[] keyBytes = toBin(key);
        byte[] cipherBytes = cipherAndMac.getCipher();
        byte[] macBytes = cipherAndMac.getMac();
        byte[] messageBytes = new byte[cipherBytes.length];


        if (!cryptoSecretBoxOpenDetached(messageBytes, cipherBytes, macBytes, cipherBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not decrypt detached message.");
        }

        return str(messageBytes);
    }




    //// -------------------------------------------|
    //// CRYPTO BOX
    //// -------------------------------------------|

    @Override
    public boolean cryptoBoxKeypair(byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_box_keypair(publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        return successful(getSodium().crypto_box_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoScalarMultBase(byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_scalarmult_base(publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxEasy(byte[] cipherText, byte[] message, long messageLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_box_easy(cipherText, message, messageLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxOpenEasy(byte[] message, byte[] cipherText, long cipherTextLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_box_open_easy(message, cipherText, cipherTextLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxDetached(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_box_detached(cipherText, mac, message, messageLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxOpenDetached(byte[] message, byte[] cipherText, byte[] mac, byte[] cipherTextLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_box_open_detached(message, cipherText, mac, cipherTextLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxBeforeNm(byte[] k, byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_box_beforenm(k, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxEasyAfterNm(byte[] cipherText, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_box_easy_afternm(cipherText, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxOpenEasyAfterNm(byte[] message, byte[] cipher, long cLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_box_open_easy_afternm(message, cipher, cLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxDetachedAfterNm(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_box_detached_afternm(cipherText, mac, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxOpenDetachedAfterNm(byte[] message, byte[] cipherText, byte[] mac, long cipherTextLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_box_open_detached_afternm(message, cipherText, mac, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxSeal(byte[] cipher, byte[] message, long messageLen, byte[] publicKey) {
        return successful(getSodium().crypto_box_seal(cipher, message, messageLen, publicKey));
    }

    @Override
    public boolean cryptoBoxSealOpen(byte[] m, byte[] cipher, long cipherLen, byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_box_seal_open(m, cipher, cipherLen, publicKey, secretKey));
    }

    // -- lazy

    @Override
    public KeyPair cryptoBoxKeypair() throws SodiumException {
        byte[] publicKey = randomBytesBuf(Box.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Box.SECRETKEYBYTES);
        if (!cryptoBoxKeypair(publicKey, secretKey)) {
            throw new SodiumException("Unable to create a public and private key.");
        }
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public KeyPair cryptoBoxSeedKeypair(byte[] seed) throws SodiumException {
        byte[] publicKey = randomBytesBuf(Box.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Box.SECRETKEYBYTES);
        if (!Box.Checker.checkSeed(seed.length)) {
            throw new SodiumException("Seed is incorrect size.");
        }
        if (!cryptoBoxSeedKeypair(publicKey, secretKey, seed)) {
            throw new SodiumException("Unable to create a public and private key.");
        }
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public KeyPair cryptoScalarMultBase(byte[] secretKey) throws SodiumException {
        if (!Box.Checker.checkSecretKey(secretKey.length)) {
            throw new SodiumException("Secret key is incorrect size.");
        }
        byte[] publicKey = randomBytesBuf(Box.PUBLICKEYBYTES);
        cryptoScalarMultBase(publicKey, secretKey);
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public KeyPair cryptoScalarMultBase(String secretKey) throws SodiumException {
        byte[] secretKeyBytes = toBin(secretKey);
        return cryptoScalarMultBase(secretKeyBytes);
    }

    @Override
    public String cryptoBoxEasy(String message, byte[] nonce, KeyPair keyPair) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] cipherBytes = new byte[Box.MACBYTES + messageBytes.length];
        boolean res = cryptoBoxEasy(
                cipherBytes,
                messageBytes,
                messageBytes.length,
                nonce,
                keyPair.getPublicKey(),
                keyPair.getSecretKey()
        );
        if (!res) {
            throw new SodiumException("Could not encrypt your message.");
        }
        return toHex(cipherBytes);
    }

    @Override
    public String cryptoBoxOpenEasy(String cipherText, byte[] nonce, KeyPair keyPair) throws SodiumException {
        byte[] cipher = toBin(cipherText);
        byte[] message = new byte[cipher.length - Box.MACBYTES];
        boolean res =
                cryptoBoxOpenEasy(message, cipher, cipher.length, nonce, keyPair.getPublicKey(), keyPair.getSecretKey());

        if (!res) {
            throw new SodiumException("Could not decrypt your message.");
        }

        return str(message);
    }

    @Override
    public String cryptoBoxBeforeNm(byte[] publicKey, byte[] secretKey) throws SodiumException {
        byte[] sharedKey = new byte[Box.BEFORENMBYTES];
        if (!Box.Checker.checkPublicKey(publicKey.length)) {
            throw new SodiumException("Public key length is incorrect.");
        }
        if (!Box.Checker.checkSecretKey(secretKey.length)) {
            throw new SodiumException("Secret key length is incorrect.");
        }
        boolean res = cryptoBoxBeforeNm(sharedKey, publicKey, secretKey);
        if (!res) {
            throw new SodiumException("Unable to encrypt using shared secret key.");
        }
        return toHex(sharedKey);
    }

    @Override
    public String cryptoBoxBeforeNm(KeyPair keyPair) throws SodiumException {
        return cryptoBoxBeforeNm(keyPair.getPublicKey(), keyPair.getSecretKey());
    }

    @Override
    public String cryptoBoxEasyAfterNm(String message, byte[] nonce, String sharedSecretKey) throws SodiumException {
        if (!Box.Checker.checkNonce(nonce.length)) {
            throw new SodiumException("Incorrect nonce length.");
        }

        byte[] sharedKey = toBin(sharedSecretKey);

        if (!Box.Checker.checkBeforeNmBytes(sharedKey.length)) {
            throw new SodiumException("Incorrect shared secret key length.");
        }

        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[messageBytes.length + Box.MACBYTES];

        boolean res = cryptoBoxEasyAfterNm(cipher, messageBytes, messageBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key encryption.");
        }

        return toHex(cipher);
    }

    @Override
    public String cryptoBoxOpenEasyAfterNm(String cipher, byte[] nonce, String sharedSecretKey) throws SodiumException {
        if (!Box.Checker.checkNonce(nonce.length)) {
            throw new SodiumException("Incorrect nonce length.");
        }

        byte[] sharedKey = toBin(sharedSecretKey);
        if (!Box.Checker.checkBeforeNmBytes(sharedKey.length)) {
            throw new SodiumException("Incorrect shared secret key length.");
        }

        byte[] cipherBytes = toBin(cipher);
        byte[] message = new byte[cipherBytes.length - Box.MACBYTES];

        boolean res = cryptoBoxOpenEasyAfterNm(message, cipherBytes, cipherBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key decryption.");
        }

        return str(message);
    }

    @Override
    public DetachedEncrypt cryptoBoxDetachedAfterNm(String message, byte[] nonce, String sharedSecretKey) throws SodiumException {
        if (!Box.Checker.checkNonce(nonce.length)) {
            throw new SodiumException("Incorrect nonce length.");
        }

        byte[] sharedKey = toBin(sharedSecretKey);

        if (!Box.Checker.checkBeforeNmBytes(sharedKey.length)) {
            throw new SodiumException("Incorrect shared secret key length.");
        }

        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[messageBytes.length];
        byte[] mac = new byte[Box.MACBYTES];


        boolean res = cryptoBoxDetachedAfterNm(cipher, mac, messageBytes, messageBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key detached encryption.");
        }


        return new DetachedEncrypt(cipher, mac);
    }

    @Override
    public DetachedDecrypt cryptoBoxOpenDetachedAfterNm(DetachedEncrypt detachedEncrypt, byte[] nonce, String sharedSecretKey) throws SodiumException {
        if (!Box.Checker.checkNonce(nonce.length)) {
            throw new SodiumException("Incorrect nonce length.");
        }

        byte[] sharedKey = toBin(sharedSecretKey);
        if (!Box.Checker.checkBeforeNmBytes(sharedKey.length)) {
            throw new SodiumException("Incorrect shared secret key length.");
        }

        byte[] cipherBytes = detachedEncrypt.getCipher();
        byte[] mac = detachedEncrypt.getMac();
        byte[] message = new byte[cipherBytes.length];

        boolean res = cryptoBoxOpenDetachedAfterNm(message, cipherBytes, mac, cipherBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key detached decryption.");
        }

        return new DetachedDecrypt(message, mac);
    }


    //// -------------------------------------------|
    //// CRYPTO SIGN
    //// -------------------------------------------|

    @Override
    public boolean cryptoSignKeypair(byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_sign_keypair(publicKey, secretKey));
    }


    @Override
    public boolean cryptoSignSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        return successful(getSodium().crypto_sign_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoSign(byte[] signedMessage, long[] signedMessageLen, byte[] message, long messageLen, byte[] secretKey) {
        return successful(getSodium().crypto_sign(signedMessage, signedMessageLen, message, messageLen, secretKey));
    }

    @Override
    public boolean cryptoSignOpen(byte[] message, long[] messageLen, byte[] signedMessage, long signedMessageLen, byte[] publicKey) {
        return successful(getSodium().crypto_sign_open(message, messageLen, signedMessage, signedMessageLen, publicKey));
    }

    @Override
    public boolean cryptoSignDetached(byte[] signature, long[] sigLength, byte[] message, long messageLen, byte[] secretKey) {
        return successful(getSodium().crypto_sign_detached(signature, sigLength, message, messageLen, secretKey));
    }

    @Override
    public boolean cryptoSignVerifyDetached(byte[] signature, byte[] message, long messageLen, byte[] publicKey) {
        return successful(getSodium().crypto_sign_verify_detached(signature, message, messageLen, publicKey));
    }

    @Override
    public boolean convertPublicKeyEd25519ToCurve25519(byte[] curve, byte[] ed) {
        return successful(getSodium().crypto_sign_ed25519_pk_to_curve25519(curve, ed));
    }

    @Override
    public boolean convertSecretKeyEd25519ToCurve25519(byte[] curve, byte[] ed) {
        return successful(getSodium().crypto_sign_ed25519_sk_to_curve25519(curve, ed));
    }

    // -- lazy

    @Override
    public KeyPair cryptoSignKeypair() throws SodiumException {
        byte[] publicKey = randomBytesBuf(Sign.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Sign.SECRETKEYBYTES);
        if (!cryptoSignKeypair(publicKey, secretKey)) {
            throw new SodiumException("Could not generate a signing keypair.");
        }
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public KeyPair cryptoSignSeedKeypair(byte[] seed) throws SodiumException {
        byte[] publicKey = randomBytesBuf(Sign.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Sign.SECRETKEYBYTES);
        if (!cryptoSignSeedKeypair(publicKey, secretKey, seed)) {
            throw new SodiumException("Could not generate a signing keypair with a seed.");
        }
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public String cryptoSign(String message, String secretKey) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] secretKeyBytes = sodiumHex2Bin(secretKey);
        byte[] signedMessage = randomBytesBuf(Sign.BYTES + messageBytes.length);
        boolean res = cryptoSign(signedMessage, null, messageBytes, messageBytes.length, secretKeyBytes);

        if (!res) {
            throw new SodiumException("Could not sign your message.");
        }

        return sodiumBin2Hex(signedMessage);
    }

    @Override
    public String cryptoSignOpen(String signedMessage, String publicKey) {
        byte[] signedMessageBytes = toBin(signedMessage);
        byte[] publicKeyBytes = sodiumHex2Bin(publicKey);

        byte[] messageBytes = randomBytesBuf(signedMessageBytes.length - Sign.BYTES);

        boolean res = cryptoSignOpen(
                messageBytes,
                null,
                signedMessageBytes,
                signedMessageBytes.length,
                publicKeyBytes
        );

        if (!res) {
            return null;
        }

        return str(messageBytes);
    }

    @Override
    public String cryptoSignDetached(String message, String secretKey) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] skBytes = toBin(secretKey);
        byte[] signatureBytes = new byte[Sign.BYTES];

        if (!cryptoSignDetached(signatureBytes, new long[1], messageBytes, messageBytes.length, skBytes)) {
            throw new SodiumException("Could not create a signature for your message in detached mode.");
        }

        return toHex(signatureBytes);
    }

    @Override
    public boolean cryptoSignVerifyDetached(String signature, String message, String publicKey) {
        byte[] messageBytes = bytes(message);
        byte[] pkBytes = toBin(publicKey);
        byte[] signatureBytes = toBin(signature);

        return cryptoSignVerifyDetached(signatureBytes, messageBytes, messageBytes.length, pkBytes);
    }

    @Override
    public KeyPair convertKeyPairEd25519ToCurve25519(KeyPair ed25519KeyPair) throws SodiumException {
        byte[] edPkBytes = ed25519KeyPair.getPublicKey();
        byte[] edSkBytes = ed25519KeyPair.getSecretKey();

        byte[] curvePkBytes = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        byte[] curveSkBytes = new byte[Sign.CURVE25519_SECRETKEYBYTES];

        boolean pkSuccess = convertPublicKeyEd25519ToCurve25519(curvePkBytes, edPkBytes);
        boolean skSuccess = convertSecretKeyEd25519ToCurve25519(curveSkBytes, edSkBytes);

        if (!pkSuccess || !skSuccess){
            throw new SodiumException("Could not convert this key pair.");
        }

        return new KeyPair(curvePkBytes, curveSkBytes);
    }


    //// -------------------------------------------|
    //// SECRET SCREAM
    //// -------------------------------------------|

    @Override
    public void cryptoSecretStreamKeygen(byte[] key) {
        getSodium().crypto_secretstream_xchacha20poly1305_keygen(key);
    }

    @Override
    public boolean cryptoSecretStreamInitPush(SecretStream.State state, byte[] header, byte[] key) {
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_init_push(state, header, key));
    }

    @Override
    public boolean cryptoSecretStreamPush(SecretStream.State state, byte[] cipher, long[] cipherAddr, byte[] message, long messageLen, byte tag) {
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                cipherAddr,
                message,
                messageLen,
                new byte[0],
                0L,
                tag
        ));
    }

    @Override
    public boolean cryptoSecretStreamPush(SecretStream.State state,
                                          byte[] cipher,
                                          byte[] message,
                                          long messageLen,
                                          byte tag) {
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                null,
                message,
                messageLen,
                new byte[0],
                0L,
                tag
        ));
    }

    @Override
    public boolean cryptoSecretStreamPush(SecretStream.State state,
                                          byte[] cipher,
                                          long[] cipherAddr,
                                          byte[] message,
                                          long messageLen,
                                          byte[] additionalData,
                                          long additionalDataLen,
                                          byte tag) {
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                cipherAddr,
                message,
                messageLen,
                additionalData,
                additionalDataLen,
                tag
        ));
    }

    @Override
    public boolean cryptoSecretStreamInitPull(SecretStream.State state, byte[] header, byte[] key) {
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_init_pull(state, header, key));
    }

    @Override
    public boolean cryptoSecretStreamPull(SecretStream.State state,
                                          byte[] message,
                                          long[] messageAddress,
                                          byte[] tag,
                                          byte[] cipher,
                                          long cipherLen,
                                          byte[] additionalData,
                                          long additionalDataLen) {
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_pull(
                state, message, messageAddress, tag, cipher, cipherLen, additionalData, additionalDataLen
        ));
    }

    @Override
    public boolean cryptoSecretStreamPull(SecretStream.State state, byte[] message, byte[] tag, byte[] cipher, long cipherLen) {
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_pull(
                state,
                message,
                new long[1],
                tag,
                cipher,
                cipherLen,
                new byte[0],
                0L
        ));
    }

    @Override
    public String cryptoSecretStreamKeygen() {
        byte[] key = randomBytesBuf(SecretStream.KEYBYTES);
        getSodium().crypto_secretstream_xchacha20poly1305_keygen(key);
        return toHex(key);
    }

    @Override
    public SecretStream.State cryptoSecretStreamInitPush(byte[] header, String key) throws SodiumException {
        SecretStream.State state = new SecretStream.State.ByReference();
        if (!SecretStream.Checker.headerCheck(header.length)) {
            throw new SodiumException("Header of secret stream incorrect length.");
        }
        getSodium().crypto_secretstream_xchacha20poly1305_init_push(state, header, toBin(key));
        return state;
    }

    @Override
    public String cryptoSecretStreamPush(SecretStream.State state, String message, byte tag) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[SecretStream.ABYTES + messageBytes.length];
        int res = getSodium().crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                null,
                messageBytes,
                messageBytes.length,
                new byte[0],
                0L,
                tag
        );

        if (res != 0) {
            throw new SodiumException("Error when encrypting a message using secret stream.");
        }

        return toHex(cipher);
    }

    @Override
    public SecretStream.State cryptoSecretStreamInitPull(byte[] header, String key) throws SodiumException {
        SecretStream.State state = new SecretStream.State.ByReference();
        if (!SecretStream.Checker.headerCheck(header.length)) {
            throw new SodiumException("Header of secret stream incorrect length.");
        }

        int res = getSodium().crypto_secretstream_xchacha20poly1305_init_pull(state, header, toBin(key));

        if (res != 0) {
            throw new SodiumException("Could not initialise a decryption state.");
        }

        return state;
    }

    @Override
    public String cryptoSecretStreamPull(SecretStream.State state, String cipher, byte[] tag) throws SodiumException {
        byte[] cipherBytes = toBin(cipher);
        byte[] message = new byte[cipherBytes.length - SecretStream.ABYTES];

        int res = getSodium().crypto_secretstream_xchacha20poly1305_pull(
                state,
                message,
                null,
                tag,
                cipherBytes,
                cipherBytes.length,
                new byte[0],
                0L
        );

        if (res != 0) {
            throw new SodiumException("Error when decrypting a message using secret stream.");
        }

        return str(message);
    }

    @Override
    public void cryptoSecretStreamRekey(SecretStream.State state) {
        getSodium().crypto_secretstream_xchacha20poly1305_rekey(state);
    }




    //// -------------------------------------------|
    //// CRYPTO AUTH
    //// -------------------------------------------|

    @Override
    public boolean cryptoAuth(byte[] tag, byte[] in, long inLen, byte[] key) {
        return successful(getSodium().crypto_auth(tag, in, inLen, key));
    }

    @Override
    public boolean cryptoAuthVerify(byte[] tag, byte[] in, long inLen, byte[] key) {
        return successful(getSodium().crypto_auth_verify(tag, in, inLen, key));
    }

    @Override
    public void cryptoAuthKeygen(byte[] k) {
        getSodium().crypto_auth_keygen(k);
    }


    @Override
    public String cryptoAuthKeygen() {
        byte[] key = randomBytesBuf(Auth.KEYBYTES);
        cryptoAuthKeygen(key);
        return toHex(key);
    }

    @Override
    public String cryptoAuth(String message, String key) throws SodiumException {
        byte[] tag = randomBytesBuf(Auth.BYTES);
        byte[] messageBytes = bytes(message);
        byte[] keyBytes = toBin(key);
        boolean res = cryptoAuth(tag, messageBytes, messageBytes.length, keyBytes);

        if (!res) {
            throw new SodiumException("Could not apply auth tag to your message.");
        }

        return toHex(tag);
    }

    @Override
    public boolean cryptoAuthVerify(String tag, String message, String key) {
        byte[] tagToBytes = toBin(tag);
        byte[] messageBytes = bytes(message);
        byte[] keyBytes = toBin(key);
        return cryptoAuthVerify(tagToBytes, messageBytes, messageBytes.length, keyBytes);
    }


    @Override
    public void cryptoAuthHMACSha256Keygen(byte[] key) {
        getSodium().crypto_auth_hmacsha256_keygen(key);
    }

    @Override
    public boolean cryptoAuthHMACSha256(byte[] out, byte[] in, int inLen, byte[] k) {
        return successful(getSodium().crypto_auth_hmacsha256(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha256Verify(byte[] h, byte[] in, int inLen, byte[] k) {
        return successful(getSodium().crypto_auth_hmacsha256_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha256Init(Auth.StateHMAC256 state, byte[] key, int keyLen) {
        return successful(getSodium().crypto_auth_hmacsha256_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha256Update(Auth.StateHMAC256 state, byte[] in, long inLen) {
        return successful(getSodium().crypto_auth_hmacsha256_update(state, in, inLen));
    }

    @Override
    public boolean cryptoAuthHMACSha256Final(Auth.StateHMAC256 state, byte[] out) {
        return successful(getSodium().crypto_auth_hmacsha256_final(state, out));
    }


    @Override
    public void cryptoAuthHMACSha512Keygen(byte[] key) {
        getSodium().crypto_auth_hmacsha512_keygen(key);
    }

    @Override
    public boolean cryptoAuthHMACSha512(byte[] out, byte[] in, int inLen, byte[] k) {
        return successful(getSodium().crypto_auth_hmacsha512(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512Verify(byte[] h, byte[] in, int inLen, byte[] k) {
        return successful(getSodium().crypto_auth_hmacsha512_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512Init(Auth.StateHMAC512 state, byte[] key, int keyLen) {
        return successful(getSodium().crypto_auth_hmacsha512_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512Update(Auth.StateHMAC512 state, byte[] in, long inLen) {
        return successful(getSodium().crypto_auth_hmacsha512_update(state, in, inLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512Final(Auth.StateHMAC512 state, byte[] out) {
        return successful(getSodium().crypto_auth_hmacsha512_final(state, out));
    }

    @Override
    public void cryptoAuthHMACSha512256Keygen(byte[] key) {
        getSodium().crypto_auth_hmacsha512256_keygen(key);
    }

    @Override
    public boolean cryptoAuthHMACSha512256(byte[] out, byte[] in, int inLen, byte[] k) {
        return successful(getSodium().crypto_auth_hmacsha512256(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Verify(byte[] h, byte[] in, int inLen, byte[] k) {
        return successful(getSodium().crypto_auth_hmacsha512256_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Init(Auth.StateHMAC512256 state, byte[] key, int keyLen) {
        return successful(getSodium().crypto_auth_hmacsha512256_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Update(Auth.StateHMAC512256 state, byte[] in, long inLen) {
        return successful(getSodium().crypto_auth_hmacsha512256_update(state, in, inLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Final(Auth.StateHMAC512256 state, byte[] out) {
        return successful(getSodium().crypto_auth_hmacsha512256_final(state, out));
    }



    @Override
    public String cryptoAuthHMACShaKeygen(Auth.Type type) {
        if (type.equals(Auth.Type.SHA256)) {
            byte[] k = new byte[Auth.HMACSHA256_KEYBYTES];
            cryptoAuthHMACSha256Keygen(k);
            return toHex(k);
        } else if (type.equals(Auth.Type.SHA512)) {
            byte[] k = new byte[Auth.HMACSHA512_KEYBYTES];
            cryptoAuthHMACSha512Keygen(k);
            return toHex(k);
        } else {
            byte[] k = new byte[Auth.HMACSHA512256_KEYBYTES];
            cryptoAuthHMACSha512256Keygen(k);
            return toHex(k);
        }
    }

    @Override
    public String cryptoAuthHMACSha(Auth.Type type, String in, String key) {
        byte[] inBytes = bytes(in);
        byte[] keyBytes = toBin(key);
        if (type.equals(Auth.Type.SHA256)) {
            byte[] out = new byte[Auth.HMACSHA256_BYTES];
            cryptoAuthHMACSha256(out, inBytes, inBytes.length, keyBytes);
            return toHex(out);
        } else if (type.equals(Auth.Type.SHA512)) {
            byte[] out = new byte[Auth.HMACSHA512_BYTES];
            cryptoAuthHMACSha512(out, inBytes, inBytes.length, keyBytes);
            return toHex(out);
        } else {
            byte[] out = new byte[Auth.HMACSHA512256_BYTES];
            cryptoAuthHMACSha512256(out, inBytes, inBytes.length, keyBytes);
            return toHex(out);
        }
    }

    @Override
    public boolean cryptoAuthHMACShaVerify(Auth.Type type, String h, String in, String key) {
        byte[] authBytes = toBin(h);
        byte[] inBytes = bytes(in);
        byte[] keyBytes = toBin(key);
        if (type.equals(Auth.Type.SHA256)) {
            return cryptoAuthHMACSha256Verify(authBytes, inBytes, inBytes.length, keyBytes);
        } else if (type.equals(Auth.Type.SHA512)) {
            return cryptoAuthHMACSha512Verify(authBytes, inBytes, inBytes.length, keyBytes);
        } else {
            return cryptoAuthHMACSha512256Verify(authBytes, inBytes, inBytes.length, keyBytes);
        }
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC256 state, String key) {
        byte[] keyBytes = toBin(key);
        return cryptoAuthHMACSha256Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC256 state, String in) {
        byte[] inBytes = bytes(in);
        return cryptoAuthHMACSha256Update(state, inBytes, inBytes.length);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC256 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA256_BYTES];
        boolean res = cryptoAuthHMACSha256Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise SHA Hash.");
        }
        return toHex(out);
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC512 state, String key) {
        byte[] keyBytes = toBin(key);
        return cryptoAuthHMACSha512Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC512 state, String in) {
        byte[] inBytes = bytes(in);
        return cryptoAuthHMACSha512Update(state, inBytes, inBytes.length);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC512 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA512_BYTES];
        boolean res = cryptoAuthHMACSha512Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise HMAC Sha 512.");
        }
        return toHex(out);
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC512256 state, String key) {
        byte[] keyBytes = toBin(key);
        return cryptoAuthHMACSha512256Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC512256 state, String in) {
        byte[] inBytes = bytes(in);
        return cryptoAuthHMACSha512256Update(state, inBytes, inBytes.length);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC512256 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA512256_BYTES];
        boolean res = cryptoAuthHMACSha512256Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise HMAC Sha 512256.");
        }
        return toHex(out);
    }

    //// -------------------------------------------|
    //// SHORT HASH
    //// -------------------------------------------|

    @Override
    public boolean cryptoShortHash(byte[] out, byte[] in, long inLen, byte[] key) {
        return successful(getSodium().crypto_shorthash(out, in, inLen, key));
    }

    @Override
    public void cryptoShortHashKeygen(byte[] k) {
        getSodium().crypto_shorthash_keygen(k);
    }

    @Override
    public String cryptoShortHash(String in, String key) throws SodiumException {
        byte[] inBytes = hexToBytes(in);
        byte[] keyBytes = hexToBytes(key);
        byte[] out = randomBytesBuf(ShortHash.BYTES);
        if (getSodium().crypto_shorthash(out, inBytes, inBytes.length, keyBytes) != 0) {
            throw new SodiumException("Failed short-input hashing.");
        }
        return sodiumBin2Hex(out);
    }

    @Override
    public String cryptoShortHashKeygen() {
        byte[] key = randomBytesBuf(ShortHash.SIPHASH24_KEYBYTES);
        getSodium().crypto_shorthash_keygen(key);
        return sodiumBin2Hex(key);
    }




    //// -------------------------------------------|
    //// GENERIC HASH
    //// -------------------------------------------|

    @Override
    public boolean cryptoGenericHash(byte[] out, int outLen, byte[] in, long inLen, byte[] key, int keyLen) {
        return successful(getSodium().crypto_generichash(out, outLen, in, inLen, key, keyLen));
    }

    @Override
    public boolean cryptoGenericHash(byte[] out, int outLen, byte[] in, long inLen) {
        return successful(getSodium().crypto_generichash(out, outLen, in, inLen, null, 0));
    }

    @Override
    public boolean cryptoGenericHashInit(byte[] state, byte[] key, int keyLength, int outLen) {
        return successful(getSodium().crypto_generichash_init(state, key, keyLength, outLen));
    }

    @Override
    public boolean cryptoGenericHashInit(byte[] state, int outLen) {
        return successful(getSodium().crypto_generichash_init(state, null, 0, outLen));
    }

    @Override
    public boolean cryptoGenericHashUpdate(byte[] state, byte[] in, long inLen) {
        return successful(getSodium().crypto_generichash_update(state, in, inLen));
    }

    @Override
    public boolean cryptoGenericHashFinal(byte[] state, byte[] out, int outLen) {
        return successful(getSodium().crypto_generichash_final(state, out, outLen));
    }

    @Override
    public int cryptoGenericHashStateBytes() {
        return getSodium().crypto_generichash_statebytes();
    }

    @Override
    public void cryptoGenericHashKeygen(byte[] k) {
        getSodium().crypto_generichash_keygen(k);
    }

    // -- lazy

    @Override
    public String cryptoGenericHashKeygen() {
        byte[] key = randomBytesBuf(GenericHash.KEYBYTES);
        cryptoGenericHashKeygen(key);
        return toHex(key);
    }

    @Override
    public String cryptoGenericHashKeygen(int size) throws SodiumException {
        byte[] key = randomBytesBuf(size);
        cryptoGenericHashKeygen(key);
        return toHex(key);
    }

    @Override
    public String cryptoGenericHash(String in, String key) throws SodiumException {
        byte[] message = bytes(in);
        byte[] keyBytes = toBin(key);

        byte[] hash = randomBytesBuf(GenericHash.BYTES);

        boolean res = cryptoGenericHash(hash, hash.length, message, message.length, keyBytes, keyBytes.length);

        if (!res) {
            throw new SodiumException("Could not hash the message.");
        }

        return toHex(hash);
    }

    @Override
    public String cryptoGenericHash(String in) throws SodiumException {
        byte[] message = bytes(in);
        byte[] hash = randomBytesBuf(GenericHash.BYTES);
        boolean res = cryptoGenericHash(hash, hash.length, message, message.length, null, 0);

        if (!res) {
            throw new SodiumException("Could not hash the message.");
        }

        return toHex(hash);
    }

    @Override
    public boolean cryptoGenericHashInit(byte[] state, String key, int outLen)  {
        byte[] keyBytes = toBin(key);
        return getSodium().crypto_generichash_init(state, keyBytes, keyBytes.length, outLen) == 0;
    }

    @Override
    public boolean cryptoGenericHashUpdate(byte[] state, String in) {
        byte[] inBytes = bytes(in);
        boolean res = getSodium().crypto_generichash_update(state, inBytes, inBytes.length) == 0;
        return res;
    }

    @Override
    public String cryptoGenericHashFinal(byte[] state, int outLen) throws SodiumException {
        byte[] hash = new byte[outLen];
        boolean res = getSodium().crypto_generichash_final(state, hash, hash.length) == 0;
        if (!res) {
            throw new SodiumException("Could not finalise the hashing process.");
        }
        return toHex(hash);
    }




    //// -------------------------------------------|
    //// AEAD
    //// -------------------------------------------|

    @Override
    public void cryptoAeadChaCha20Poly1305Keygen(byte[] key) {
        getSodium().crypto_aead_chacha20poly1305_keygen(key);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305Encrypt(byte[] c, long[] cLen, byte[] m, long mLen, byte[] ad, long adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_chacha20poly1305_encrypt(c, cLen, m, mLen, ad, adLen, nSec, nPub, k));
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305Decrypt(byte[] m, long[] mLen, byte[] nSec, byte[] c, long cLen, byte[] ad, long adLen, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_chacha20poly1305_decrypt(m, mLen, nSec, c, cLen, ad, adLen, nPub, k));
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305EncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, long mLen, byte[] ad, long adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_chacha20poly1305_encrypt_detached(c, mac, macLenAddress, m, mLen, ad, adLen, nSec, nPub, k));
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305DecryptDetached(byte[] m, byte[] nSec, byte[] c, long cLen, byte[] mac, byte[] ad, long adLen, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_chacha20poly1305_decrypt_detached(m, nSec, c, cLen, mac, ad, adLen, nPub, k));
    }

    @Override
    public void cryptoAeadChaCha20Poly1305IetfKeygen(byte[] key) {
        getSodium().crypto_aead_chacha20poly1305_ietf_keygen(key);
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305IetfEncrypt(byte[] c, long[] cLen, byte[] m, long mLen, byte[] ad, long adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_chacha20poly1305_ietf_encrypt(c, cLen, m, mLen, ad, adLen, nSec, nPub, k));
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305IetfDecrypt(byte[] m, long[] mLen, byte[] nSec, byte[] c, long cLen, byte[] ad, long adLen, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_chacha20poly1305_ietf_decrypt(m, mLen, nSec, c, cLen, ad, adLen, nPub, k));
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305IetfEncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, long mLen, byte[] ad, long adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, macLenAddress, m, mLen, ad, adLen, nSec, nPub, k));
    }

    @Override
    public boolean cryptoAeadChaCha20Poly1305IetfDecryptDetached(byte[] m, byte[] nSec, byte[] c, long cLen, byte[] mac, byte[] ad, long adLen, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nSec, c, cLen, mac, ad, adLen, nPub, k));
    }

    @Override
    public void cryptoAeadXChaCha20Poly1305IetfKeygen(byte[] k) {
        getSodium().crypto_aead_xchacha20poly1305_ietf_keygen(k);
    }

    @Override
    public boolean cryptoAeadXChaCha20Poly1305IetfEncrypt(byte[] c, long[] cLen, byte[] m, long mLen, byte[] ad, long adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(c, cLen, m, mLen, ad, adLen, nSec, nPub, k));
    }

    @Override
    public boolean cryptoAeadXChaCha20Poly1305IetfDecrypt(byte[] m, long[] mLen, byte[] nSec, byte[] c, long cLen, byte[] ad, long adLen, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(m, mLen, nSec, c, cLen, ad, adLen, nPub, k));
    }

    @Override
    public boolean cryptoAeadXChaCha20Poly1305IetfEncryptDetached(byte[] c, byte[] mac, long[] macLenAddress, byte[] m, long mLen, byte[] ad, long adLen, byte[] nSec, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, macLenAddress, m, mLen, ad, adLen, nSec, nPub, k));
    }

    @Override
    public boolean cryptoAeadXChaCha20Poly1305IetfDecryptDetached(byte[] m, byte[] nSec, byte[] c, long cLen, byte[] mac, byte[] ad, long adLen, byte[] nPub, byte[] k) {
        return successful(getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, nSec, c, cLen, mac, ad, adLen, nPub, k));
    }

    @Override
    public void cryptoAeadAES256GCMKeygen(byte[] key) {
        getSodium().crypto_aead_aes256gcm_keygen(key);
    }

    @Override
    public boolean cryptoAeadAES256GCMEncrypt(byte[] cipher, long[] cipherLen, byte[] message, long messageLen, byte[] additionalData, long additionalDataLen, byte[] nSec, byte[] nPub, byte[] key) {
        return successful(getSodium().crypto_aead_aes256gcm_encrypt(cipher, cipherLen, message, messageLen, additionalData, additionalDataLen, nSec, nPub, key));
    }

    @Override
    public boolean cryptoAeadAES256GCMDecrypt(byte[] message, long[] messageLen, byte[] nSec, byte[] cipher, long cipherLen, byte[] additionalData, long additionalDataLen, byte[] nPub, byte[] key) {
        return successful(getSodium().crypto_aead_aes256gcm_decrypt(message, messageLen, nSec, cipher, cipherLen, additionalData, additionalDataLen, nPub, key));
    }

    @Override
    public boolean cryptoAeadAES256GCMEncryptDetached(byte[] cipher, byte[] mac, long[] macLenAddress, byte[] message, long messageLen, byte[] additionalData, long additionalDataLen, byte[] nSec, byte[] nPub, byte[] key) {
        return successful(getSodium().crypto_aead_aes256gcm_encrypt_detached(cipher, mac, macLenAddress, message, messageLen, additionalData, additionalDataLen, nSec, nPub, key));
    }

    @Override
    public boolean cryptoAeadAES256GCMDecryptDetached(byte[] message, byte[] nSec, byte[] cipher, long cipherLen, byte[] mac, byte[] additionalData, long additionalDataLen, byte[] nPub, byte[] key) {
        return successful(getSodium().crypto_aead_aes256gcm_decrypt_detached(message, nSec, cipher, cipherLen, mac, additionalData, additionalDataLen, nPub, key));
    }


    // -- lazy

    @Override
    public String keygen(AEAD.Method method) {
        switch (method) {
            case CHACHA20_POLY1305:
                byte[] key = randomBytesBuf(AEAD.CHACHA20POLY1305_KEYBYTES);
                cryptoAeadChaCha20Poly1305Keygen(key);
                return toHex(key);
            case CHACHA20_POLY1305_IETF:
                byte[] key2 = randomBytesBuf(AEAD.CHACHA20POLY1305_IETF_KEYBYTES);
                cryptoAeadChaCha20Poly1305IetfKeygen(key2);
                return toHex(key2);
            case XCHACHA20_POLY1305_IETF:
                byte[] key3 = randomBytesBuf(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES);
                cryptoAeadChaCha20Poly1305IetfKeygen(key3);
                return toHex(key3);
            case AES256GCM:
                byte[] key4 = randomBytesBuf(AEAD.AES256GCM_KEYBYTES);
                cryptoAeadAES256GCMKeygen(key4);
                return toHex(key4);
        }
        return null;
    }

    @Override
    public String encrypt(String m, String additionalData, byte[] nPub, String k, AEAD.Method method) {
        return encrypt(m, additionalData, null, nPub,  k, method);
    }

    @Override
    public String encrypt(String m, String additionalData, byte[] nSec, byte[] nPub, String k, AEAD.Method method) {
        byte[] messageBytes = bytes(m);
        byte[] additionalDataBytes = additionalData == null ? new byte[0] : bytes(additionalData);
        long additionalBytesLen = additionalData == null ? 0L : additionalDataBytes.length;
        byte[] keyBytes = toBin(k);

        if (method.equals(AEAD.Method.CHACHA20_POLY1305)) {
            byte[] cipherBytes = new byte[messageBytes.length + AEAD.CHACHA20POLY1305_ABYTES];
            cryptoAeadChaCha20Poly1305Encrypt(
                    cipherBytes,
                    null,
                    messageBytes,
                    messageBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nSec,
                    nPub,
                    keyBytes
            );
            return toHex(cipherBytes);
        } else if (method.equals(AEAD.Method.CHACHA20_POLY1305_IETF)) {
            byte[] cipherBytes = new byte[messageBytes.length + AEAD.CHACHA20POLY1305_IETF_ABYTES];
            cryptoAeadChaCha20Poly1305IetfEncrypt(
                    cipherBytes,
                    null,
                    messageBytes,
                    messageBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nSec,
                    nPub,
                    keyBytes
            );
            return toHex(cipherBytes);
        } else if (method.equals(AEAD.Method.XCHACHA20_POLY1305_IETF)) {
            byte[] cipherBytes3 = new byte[messageBytes.length + AEAD.XCHACHA20POLY1305_IETF_ABYTES];
            cryptoAeadXChaCha20Poly1305IetfEncrypt(
                    cipherBytes3,
                    null,
                    messageBytes,
                    messageBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nSec,
                    nPub,
                    keyBytes
            );
            return toHex(cipherBytes3);
        } else {
            byte[] cipherBytes = new byte[messageBytes.length + AEAD.AES256GCM_ABYTES];
            cryptoAeadAES256GCMEncrypt(
                    cipherBytes,
                    null,
                    messageBytes,
                    messageBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nSec,
                    nPub,
                    keyBytes
            );
            return toHex(cipherBytes);
        }
    }


    @Override
    public String decrypt(String cipher, String additionalData, byte[] nPub, String k, AEAD.Method method) {
        return decrypt(cipher, additionalData, null, nPub, k, method);
    }

    @Override
    public String decrypt(String cipher, String additionalData, byte[] nSec, byte[] nPub, String k, AEAD.Method method) {
        byte[] cipherBytes = toBin(cipher);
        byte[] additionalDataBytes = additionalData == null ? new byte[0] : bytes(additionalData);
        long additionalBytesLen = additionalData == null ? 0L : additionalDataBytes.length;
        byte[] keyBytes = toBin(k);

        if (method.equals(AEAD.Method.CHACHA20_POLY1305)) {
            byte[] messageBytes = new byte[cipherBytes.length - AEAD.CHACHA20POLY1305_ABYTES];
            cryptoAeadChaCha20Poly1305Decrypt(
                    messageBytes,
                    null,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            );
            return str(messageBytes);
        } else if (method.equals(AEAD.Method.CHACHA20_POLY1305_IETF)) {
            byte[] messageBytes = new byte[cipherBytes.length - AEAD.CHACHA20POLY1305_IETF_ABYTES];
            cryptoAeadChaCha20Poly1305IetfDecrypt(
                    messageBytes,
                    null,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            );
            return str(messageBytes);
        } else if (method.equals(AEAD.Method.XCHACHA20_POLY1305_IETF)) {
            byte[] messageBytes = new byte[cipherBytes.length - AEAD.XCHACHA20POLY1305_IETF_ABYTES];
            cryptoAeadXChaCha20Poly1305IetfDecrypt(
                    messageBytes,
                    null,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            );
            return str(messageBytes);
        } else {
            byte[] messageBytes = new byte[cipherBytes.length - AEAD.AES256GCM_ABYTES];
            cryptoAeadAES256GCMDecrypt(
                    messageBytes,
                    null,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            );
            return str(messageBytes);
        }
    }

    @Override
    public DetachedEncrypt encryptDetached(String m, String additionalData, byte[] nSec, byte[] nPub, String k, AEAD.Method method) {
        byte[] messageBytes = bytes(m);
        byte[] additionalDataBytes = additionalData == null ? new byte[0] : bytes(additionalData);
        long additionalBytesLen = additionalData == null ? 0L : additionalDataBytes.length;
        byte[] keyBytes = toBin(k);
        byte[] cipherBytes = new byte[messageBytes.length];

        if (method.equals(AEAD.Method.CHACHA20_POLY1305)) {
            byte[] macBytes = new byte[AEAD.CHACHA20POLY1305_ABYTES];

            cryptoAeadChaCha20Poly1305EncryptDetached(
                    cipherBytes,
                    macBytes,
                    null,
                    messageBytes,
                    messageBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nSec,
                    nPub,
                    keyBytes
            );
            return new DetachedEncrypt(cipherBytes, macBytes);
        } else if (method.equals(AEAD.Method.CHACHA20_POLY1305_IETF)) {
            byte[] macBytes = new byte[AEAD.CHACHA20POLY1305_IETF_ABYTES];
            cryptoAeadChaCha20Poly1305IetfEncryptDetached(
                    cipherBytes,
                    macBytes,
                    null,
                    messageBytes,
                    messageBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nSec,
                    nPub,
                    keyBytes
            );
            return new DetachedEncrypt(cipherBytes, macBytes);
        } else if (method.equals(AEAD.Method.XCHACHA20_POLY1305_IETF)) {
            byte[] macBytes = new byte[AEAD.XCHACHA20POLY1305_IETF_ABYTES];
            cryptoAeadXChaCha20Poly1305IetfEncryptDetached(
                    cipherBytes,
                    macBytes,
                    null,
                    messageBytes,
                    messageBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nSec,
                    nPub,
                    keyBytes
            );
            return new DetachedEncrypt(cipherBytes, macBytes);
        } else {
            byte[] macBytes = new byte[AEAD.AES256GCM_ABYTES];
            cryptoAeadAES256GCMEncryptDetached(
                    cipherBytes,
                    macBytes,
                    null,
                    messageBytes,
                    messageBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nSec,
                    nPub,
                    keyBytes
            );
            return new DetachedEncrypt(cipherBytes, macBytes);
        }
    }

    @Override
    public DetachedDecrypt decryptDetached(DetachedEncrypt detachedEncrypt, String additionalData, byte[] nSec, byte[] nPub, String k, AEAD.Method method) {
        byte[] cipherBytes = detachedEncrypt.getCipher();
        byte[] additionalDataBytes = additionalData == null ? new byte[0] : bytes(additionalData);
        long additionalBytesLen = additionalData == null ? 0L : additionalDataBytes.length;
        byte[] keyBytes = toBin(k);
        byte[] messageBytes = new byte[cipherBytes.length];
        byte[] macBytes = detachedEncrypt.getMac();

        if (method.equals(AEAD.Method.CHACHA20_POLY1305)) {
            cryptoAeadChaCha20Poly1305DecryptDetached(
                    messageBytes,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    macBytes,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            );
            return new DetachedDecrypt(messageBytes, macBytes, charset);
        } else if (method.equals(AEAD.Method.CHACHA20_POLY1305_IETF)) {
            cryptoAeadChaCha20Poly1305IetfDecryptDetached(
                    messageBytes,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    macBytes,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            );
            return new DetachedDecrypt(messageBytes, macBytes, charset);
        } else if (method.equals(AEAD.Method.XCHACHA20_POLY1305_IETF)) {
            cryptoAeadXChaCha20Poly1305IetfDecryptDetached(
                    messageBytes,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    macBytes,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            );
            return new DetachedDecrypt(messageBytes, macBytes, charset);
        } else {
            cryptoAeadAES256GCMDecryptDetached(
                    messageBytes,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    macBytes,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            );
            return new DetachedDecrypt(messageBytes, macBytes, charset);
        }
    }


    //// -------------------------------------------|
    //// CONVENIENCE
    //// -------------------------------------------|

    @Override
    public <T> T res(int res, T object) {
        return (res != 0) ? null : object;
    }

    @Override
    public boolean successful(int res) {
        return (res == 0);
    }

    @Override
    public String str(byte[] bs) {
        return new String(bs, charset);
    }

    @Override
    public String str(byte[] bs, Charset charset) {
        if (charset == null) {
            return new String(bs, this.charset);
        }
        return new String(bs, charset);
    }

    @Override
    public byte[] bytes(String s) {
        return s.getBytes(charset);
    }

    @Override
    public boolean wrongLen(byte[] bs, int shouldBe) {
        return bs.length != shouldBe;
    }

    @Override
    public boolean wrongLen(int byteLength, int shouldBe) {
        return byteLength != shouldBe;
    }

    @Override
    public boolean wrongLen(int byteLength, long shouldBe) {
        return byteLength != shouldBe;
    }

    @Override
    public byte[] removeNulls(byte[] bs) {
        // First determine how many bytes to
        // cut off the end by checking total of null bytes
        int totalBytesToCut = 0;
        for (int i = bs.length - 1; i >= 0; i--) {
            byte b = bs[i];
            if (b == 0) {
                totalBytesToCut++;
            }
        }

        // ... then we now can copy across the array
        // without the null bytes.
        int newLengthOfBs = bs.length - totalBytesToCut;
        byte[] trimmed = new byte[newLengthOfBs];
        System.arraycopy(bs, 0, trimmed, 0, newLengthOfBs);

        return trimmed;
    }


    public abstract Sodium getSodium();



    // --
    //// -------------------------------------------|
    //// MAIN
    //// -------------------------------------------|
    // --
    public static void main(String[] args) {
        // Can implement some code here to test
    }



}
