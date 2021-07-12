/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.*;
import com.goterl.lazysodium.interfaces.Ristretto255.Checker;
import com.goterl.lazysodium.interfaces.Ristretto255.RistrettoPoint;
import com.goterl.lazysodium.utils.*;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.math.BigInteger;
import javax.crypto.AEADBadTagException;
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
        Stream.Native, Stream.Lazy,
        Padding.Native, Padding.Lazy,
        Helpers.Native, Helpers.Lazy,
        PwHash.Native, PwHash.Lazy,
        Hash.Native, Hash.Lazy,
        Sign.Native, Sign.Lazy,
        Box.Native, Box.Lazy,
        SecretBox.Native, SecretBox.Lazy,
        KeyExchange.Native, KeyExchange.Lazy,
        KeyDerivation.Native, KeyDerivation.Lazy,
        DiffieHellman.Native, DiffieHellman.Lazy,
        Ristretto255.Native, Ristretto255.Lazy {

    protected final Charset charset;
    protected final MessageEncoder messageEncoder;

    public LazySodium(Charset charset, MessageEncoder messageEncoder) {
        this.charset = charset;
        this.messageEncoder = messageEncoder;
    }

    public LazySodium() {
        this(StandardCharsets.UTF_8, new HexMessageEncoder());
    }

    public LazySodium(Charset charset) {
        this(charset, new HexMessageEncoder());
    }

    public LazySodium(MessageEncoder messageEncoder) {
        this(StandardCharsets.UTF_8, messageEncoder);
    }

    public static Integer longToInt(long lng) {
        if (lng < 0) {
            return 0;
        }
        return Math.toIntExact(lng);
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

    public String toHexStr(byte[] bs) {
        return bytesToHex(bs);
    }

    public byte[] toBinary(String hex) {
        return hexToBytes(hex);
    }

    /**
     * Bytes to hexadecimal. Equivalent to {@link #sodiumBin2Hex(byte[])} but static.
     *
     * @param bin Byte array.
     * @return Hexadecimal string.
     */
    public static String toHex(byte[] bin) {
        return bytesToHex(bin);
    }


    /**
     * Hexadecimal string to bytes. Equivalent to {@link #sodiumHex2Bin(String)}} but static.
     *
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
        for (int j = 0; j < bytes.length; j++) {
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
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }


    //// -------------------------------------------|
    //// RANDOM
    //// -------------------------------------------|

    @Override
    public long randomBytesRandom() {
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
    public long randomBytesUniform(int upperBound) {
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
    public boolean sodiumPad(IntByReference paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize, int maxBufLen) {
        return successful(getSodium().sodium_pad(paddedBuffLen.getPointer(), buf, unpaddedBufLen, blockSize, maxBufLen));
    }

    @Override
    public boolean sodiumUnpad(IntByReference unPaddedBuffLen, char[] buf, int paddedBufLen, int blockSize) {
        return successful(getSodium().sodium_unpad(unPaddedBuffLen.getPointer(), buf, paddedBufLen, blockSize));
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
        if (masterKey.length != KeyDerivation.MASTER_KEY_BYTES) {
            throw new IllegalArgumentException("Master key length is wrong: " + masterKey.length);
        }
        getSodium().crypto_kdf_keygen(masterKey);
    }

    @Override
    public int cryptoKdfDeriveFromKey(byte[] subKey, int subKeyLen, long subKeyId, byte[] context, byte[] masterKey) {
        if (subKeyLen < KeyDerivation.BYTES_MIN || KeyDerivation.BYTES_MAX < subKeyLen) {
            throw new IllegalArgumentException("Sub Key Length is out of bounds: " + subKeyLen);
        }
        if (subKey.length < subKeyLen) {
            throw new IllegalArgumentException("Sub Key array is less than specified size");
        }
        if (masterKey.length != KeyDerivation.MASTER_KEY_BYTES) {
            throw new IllegalArgumentException("Master key length is wrong: " + masterKey.length);
        }
        if (context.length != KeyDerivation.CONTEXT_BYTES) {
            throw new IllegalArgumentException("Context length is wrong: " + context.length);
        }
        return getSodium().crypto_kdf_derive_from_key(subKey, subKeyLen, subKeyId, context, masterKey);
    }

    @Override
    public Key cryptoKdfKeygen() {
        byte[] masterKey = new byte[KeyDerivation.MASTER_KEY_BYTES];
        getSodium().crypto_kdf_keygen(masterKey);
        return Key.fromBytes(masterKey);
    }

    @Override
    public Key cryptoKdfDeriveFromKey(int lengthOfSubKey, long subKeyId, String context, Key masterKey)
            throws SodiumException {
        if (!KeyDerivation.Checker.subKeyIsCorrect(lengthOfSubKey)) {
            throw new SodiumException("Subkey is not between the correct lengths.");
        }
        if (!KeyDerivation.Checker.masterKeyIsCorrect(masterKey.getAsBytes().length)) {
            throw new SodiumException("Master key is not the correct length.");
        }
        if (!KeyDerivation.Checker.contextIsCorrect(bytes(context).length)) {
            throw new SodiumException("Context is not the correct length.");
        }

        byte[] subKey = new byte[lengthOfSubKey];
        byte[] contextAsBytes = bytes(context);
        byte[] masterKeyAsBytes = masterKey.getAsBytes();
        int res = getSodium().crypto_kdf_derive_from_key(
                subKey,
                lengthOfSubKey,
                subKeyId,
                contextAsBytes,
                masterKeyAsBytes
        );

        if (!successful(res)) {
            throw new SodiumException("Failed kdfDeriveFromKey.");
        }
        return Key.fromBytes(subKey);
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

        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    public KeyPair cryptoKxKeypair(byte[] seed) {
        byte[] secretKey = randomBytesBuf(KeyExchange.SECRETKEYBYTES);
        byte[] publicKey = randomBytesBuf(KeyExchange.PUBLICKEYBYTES);

        getSodium().crypto_kx_seed_keypair(publicKey, secretKey, seed);

        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }


    @Override
    public SessionPair cryptoKxClientSessionKeys(KeyPair clientKeyPair, KeyPair serverKeyPair) throws SodiumException {
        return cryptoKxClientSessionKeys(clientKeyPair.getPublicKey(), clientKeyPair.getSecretKey(), serverKeyPair.getPublicKey());
    }

    @Override
    public SessionPair cryptoKxServerSessionKeys(Key serverPk, Key serverSk, Key clientPk) throws SodiumException {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];

        if (!cryptoKxServerSessionKeys(rx, tx, serverPk.getAsBytes(), serverSk.getAsBytes(), clientPk.getAsBytes())) {
            throw new SodiumException("Failed creating server session keys.");
        }

        return new SessionPair(rx, tx);
    }

    @Override
    public SessionPair cryptoKxClientSessionKeys(Key clientPk, Key clientSk, Key serverPk) throws SodiumException {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];

        if (!cryptoKxClientSessionKeys(rx, tx, clientPk.getAsBytes(), clientSk.getAsBytes(), serverPk.getAsBytes())) {
            throw new SodiumException("Failed creating client session keys.");
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
                                int outputHashLen,
                                byte[] password,
                                int passwordLen,
                                byte[] salt,
                                long opsLimit,
                                NativeLong memLimit,
                                PwHash.Alg alg) {
        if (outputHashLen < 0 || outputHashLen > outputHash.length) {
            throw new IllegalArgumentException("outputHashLen out of bounds: " + outputHashLen);
        }
        if (passwordLen < 0 || passwordLen > password.length) {
            throw new IllegalArgumentException("passwordLen out of bounds: " + passwordLen);
        }
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
                                   int passwordLen,
                                   long opsLimit,
                                   NativeLong memLimit) {
        if (passwordLen < 0 || passwordLen > password.length) {
            throw new IllegalArgumentException("passwordLen out of bounds: " + passwordLen);
        }
        int res = getSodium().crypto_pwhash_str(outputStr, password, passwordLen, opsLimit, memLimit);
        return successful(res);
    }

    @Override
    public boolean cryptoPwHashStrVerify(byte[] hash, byte[] password, int passwordLen) {
        if (passwordLen < 0 || passwordLen > password.length) {
            throw new IllegalArgumentException("passwordLen out of bounds: " + passwordLen);
        }
        return successful(getSodium().crypto_pwhash_str_verify(hash, password, passwordLen));
    }

    @Override
    public boolean cryptoPwHashStrNeedsRehash(byte[] hash, long opsLimit, NativeLong memLimit) {
        return successful(getSodium().crypto_pwhash_str_needs_rehash(hash, opsLimit, memLimit));
    }


    // lazy

    @Override
    public String cryptoPwHash(String password, int lengthOfHash, byte[] salt, long opsLimit, NativeLong memLimit, PwHash.Alg alg)
            throws SodiumException {
        byte[] passwordBytes = bytes(password);
        PwHash.Checker.checkAll(passwordBytes.length, salt.length, opsLimit, memLimit);
        byte[] hash = new byte[lengthOfHash];
        int res = getSodium().crypto_pwhash(hash, hash.length, passwordBytes, passwordBytes.length, salt, opsLimit, memLimit, alg.getValue());
        if (res != 0) {
            throw new SodiumException(
                    "Could not hash your string. This may be due to insufficient " +
                            "memory or your CPU does not support Argon2's instruction set."
            );
        }
        return messageEncoder.encode(hash);
    }

    @Override
    public String cryptoPwHashStr(String password, long opsLimit, NativeLong memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }
        return messageEncoder.encode(hash);
    }

    @Override
    public String cryptoPwHashStrRemoveNulls(String password, long opsLimit, NativeLong memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }

        byte[] hashNoNulls = removeNulls(hash);
        return messageEncoder.encode(hashNoNulls);
    }

    @Override
    public boolean cryptoPwHashStrVerify(String hash, String password) {
        byte[] hashBytes = messageEncoder.decode(hash);
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
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_hash_sha256(out, in, inLen));
    }

    @Override
    public boolean cryptoHashSha256Init(Hash.State256 state) {
        return successful(getSodium().crypto_hash_sha256_init(state));
    }

    @Override
    public boolean cryptoHashSha256Update(Hash.State256 state, byte[] in, long inLen) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_hash_sha256_update(state, in, inLen));
    }

    @Override
    public boolean cryptoHashSha256Final(Hash.State256 state, byte[] out) {
        return successful(getSodium().crypto_hash_sha256_final(state, out));
    }

    @Override
    public boolean cryptoHashSha512(byte[] out, byte[] in, long inLen) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_hash_sha512(out, in, inLen));
    }

    @Override
    public boolean cryptoHashSha512Init(Hash.State512 state) {
        return successful(getSodium().crypto_hash_sha512_init(state));
    }

    @Override
    public boolean cryptoHashSha512Update(Hash.State512 state, byte[] in, long inLen) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
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
        return messageEncoder.encode(hashedBytes);
    }

    @Override
    public String cryptoHashSha512(String message) throws SodiumException {
        byte[] msgBytes = bytes(message);
        byte[] hashedBytes = new byte[Hash.SHA512_BYTES];
        if (!cryptoHashSha512(hashedBytes, msgBytes, msgBytes.length)) {
            throw new SodiumException("Unsuccessful sha-512 hash.");
        }
        return messageEncoder.encode(hashedBytes);
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
        return messageEncoder.encode(finalHash);
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
        return messageEncoder.encode(finalHash);
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
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_secretbox_easy(cipherText, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxOpenEasy(byte[] message, byte[] cipherText, long cipherTextLen, byte[] nonce, byte[] key) {
        if (cipherTextLen < 0 || cipherTextLen > cipherText.length) {
            throw new IllegalArgumentException("cipherTextLen out of bounds: " + cipherTextLen);
        }
        return successful(getSodium().crypto_secretbox_open_easy(message, cipherText, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxDetached(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_secretbox_detached(cipherText, mac, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxOpenDetached(byte[] message, byte[] cipherText, byte[] mac, long cipherTextLen, byte[] nonce, byte[] key) {
        if (cipherTextLen < 0 || cipherTextLen > cipherText.length) {
            throw new IllegalArgumentException("cipherTextLen out of bounds: " + cipherTextLen);
        }
        return successful(getSodium().crypto_secretbox_open_detached(message, cipherText, mac, cipherTextLen, nonce, key));
    }


    /// --- Lazy

    @Override
    public Key cryptoSecretBoxKeygen() {
        byte[] key = new byte[SecretBox.KEYBYTES];
        cryptoSecretBoxKeygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public String cryptoSecretBoxEasy(String message, byte[] nonce, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        byte[] messageBytes = bytes(message);
        byte[] cipherTextBytes = new byte[SecretBox.MACBYTES + messageBytes.length];

        if (!cryptoSecretBoxEasy(cipherTextBytes, messageBytes, messageBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not encrypt message.");
        }

        return messageEncoder.encode(cipherTextBytes);
    }

    @Override
    public String cryptoSecretBoxOpenEasy(String cipher, byte[] nonce, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        byte[] cipherBytes = messageEncoder.decode(cipher);
        byte[] messageBytes = new byte[cipherBytes.length - SecretBox.MACBYTES];


        if (!cryptoSecretBoxOpenEasy(messageBytes, cipherBytes, cipherBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not decrypt message.");
        }

        return str(messageBytes);
    }

    @Override
    public DetachedEncrypt cryptoSecretBoxDetached(String message, byte[] nonce, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        byte[] messageBytes = bytes(message);
        byte[] cipherTextBytes = new byte[messageBytes.length];
        byte[] macBytes = new byte[SecretBox.MACBYTES];

        if (!cryptoSecretBoxDetached(cipherTextBytes, macBytes, messageBytes, messageBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not encrypt detached message.");
        }

        return new DetachedEncrypt(cipherTextBytes, macBytes);
    }

    @Override
    public String cryptoSecretBoxOpenDetached(DetachedEncrypt cipherAndMac, byte[] nonce, Key key) throws SodiumException {
        byte[] keyBytes = key.getAsBytes();
        byte[] cipherBytes = cipherAndMac.getCipher();
        byte[] macBytes = cipherAndMac.getMac();
        byte[] messageBytes = new byte[cipherBytes.length];


        if (!cryptoSecretBoxOpenDetached(messageBytes, cipherBytes, macBytes, cipherBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not decrypt detached message.");
        }

        return str(messageBytes);
    }


    //// -------------------------------------------|
    //// DIFFIE HELLMAN
    //// -------------------------------------------|

    @Override
    public boolean cryptoScalarMultBase(byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_scalarmult_base(publicKey, secretKey));
    }

    @Override
    public Key cryptoScalarMultBase(Key secretKey) {
        byte[] publicKey = new byte[DiffieHellman.SCALARMULT_BYTES];
        cryptoScalarMultBase(publicKey, secretKey.getAsBytes());
        return Key.fromBytes(publicKey);
    }

    @Override
    public boolean cryptoScalarMult(byte[] shared, byte[] secretKey, byte[] publicKey) {
        return successful(getSodium().crypto_scalarmult(shared, secretKey, publicKey));
    }

    @Override
    public Key cryptoScalarMult(Key secretKey, Key publicKey) {
        byte[] sharedKey = new byte[DiffieHellman.SCALARMULT_BYTES];
        cryptoScalarMult(sharedKey, secretKey.getAsBytes(), publicKey.getAsBytes());
        return Key.fromBytes(sharedKey);
    }


    // -------------------------------------------|
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
    public boolean cryptoBoxEasy(byte[] cipherText, byte[] message, long messageLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_box_easy(cipherText, message, messageLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxOpenEasy(byte[] message, byte[] cipherText, long cipherTextLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        if (cipherTextLen < 0 || cipherTextLen > cipherText.length) {
            throw new IllegalArgumentException("cipherTextLen out of bounds: " + cipherTextLen);
        }
        return successful(getSodium().crypto_box_open_easy(message, cipherText, cipherTextLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxDetached(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_box_detached(cipherText, mac, message, messageLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxOpenDetached(byte[] message, byte[] cipherText, byte[] mac, long cipherTextLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        if (cipherTextLen < 0 || cipherTextLen > cipherText.length) {
            throw new IllegalArgumentException("cipherTextLen out of bounds: " + cipherTextLen);
        }
        return successful(getSodium().crypto_box_open_detached(message, cipherText, mac, cipherTextLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxBeforeNm(byte[] k, byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_box_beforenm(k, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxEasyAfterNm(byte[] cipherText, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_box_easy_afternm(cipherText, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxOpenEasyAfterNm(byte[] message, byte[] cipher, long cLen, byte[] nonce, byte[] key) {
        if (cLen < 0 || cLen > cipher.length) {
            throw new IllegalArgumentException("cLen out of bounds: " + cLen);
        }
        return successful(getSodium().crypto_box_open_easy_afternm(message, cipher, cLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxDetachedAfterNm(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_box_detached_afternm(cipherText, mac, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxOpenDetachedAfterNm(byte[] message, byte[] cipherText, byte[] mac, long cipherTextLen, byte[] nonce, byte[] key) {
        if (cipherTextLen < 0 || cipherTextLen > cipherText.length) {
            throw new IllegalArgumentException("cipherTextLen out of bounds: " + cipherTextLen);
        }
        return successful(getSodium().crypto_box_open_detached_afternm(message, cipherText, mac, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxSeal(byte[] cipher, byte[] message, long messageLen, byte[] publicKey) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_box_seal(cipher, message, messageLen, publicKey));
    }

    @Override
    public boolean cryptoBoxSealOpen(byte[] m, byte[] cipher, long cipherLen, byte[] publicKey, byte[] secretKey) {
        if (cipherLen < 0 || cipherLen > cipher.length) {
            throw new IllegalArgumentException("cipherLen out of bounds: " + cipherLen);
        }
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
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
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
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
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
                keyPair.getPublicKey().getAsBytes(),
                keyPair.getSecretKey().getAsBytes()
        );
        if (!res) {
            throw new SodiumException("Could not encrypt your message.");
        }
        return messageEncoder.encode(cipherBytes);
    }

    @Override
    public String cryptoBoxOpenEasy(String cipherText, byte[] nonce, KeyPair keyPair) throws SodiumException {
        byte[] cipher = messageEncoder.decode(cipherText);
        byte[] message = new byte[cipher.length - Box.MACBYTES];
        boolean res =
                cryptoBoxOpenEasy(
                        message,
                        cipher,
                        cipher.length,
                        nonce,
                        keyPair.getPublicKey().getAsBytes(),
                        keyPair.getSecretKey().getAsBytes()
                );

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
        return messageEncoder.encode(sharedKey);
    }

    @Override
    public String cryptoBoxBeforeNm(KeyPair keyPair) throws SodiumException {
        return cryptoBoxBeforeNm(keyPair.getPublicKey().getAsBytes(), keyPair.getSecretKey().getAsBytes());
    }

    @Override
    public String cryptoBoxEasyAfterNm(String message, byte[] nonce, String sharedSecretKey) throws SodiumException {
        if (!Box.Checker.checkNonce(nonce.length)) {
            throw new SodiumException("Incorrect nonce length.");
        }

        byte[] sharedKey = messageEncoder.decode(sharedSecretKey);

        if (!Box.Checker.checkBeforeNmBytes(sharedKey.length)) {
            throw new SodiumException("Incorrect shared secret key length.");
        }

        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[messageBytes.length + Box.MACBYTES];

        boolean res = cryptoBoxEasyAfterNm(cipher, messageBytes, messageBytes.length, nonce, sharedKey);
        if (!res) {
            throw new SodiumException("Could not fully complete shared secret key encryption.");
        }

        return messageEncoder.encode(cipher);
    }

    @Override
    public String cryptoBoxOpenEasyAfterNm(String cipher, byte[] nonce, String sharedSecretKey) throws SodiumException {
        if (!Box.Checker.checkNonce(nonce.length)) {
            throw new SodiumException("Incorrect nonce length.");
        }

        byte[] sharedKey = messageEncoder.decode(sharedSecretKey);
        if (!Box.Checker.checkBeforeNmBytes(sharedKey.length)) {
            throw new SodiumException("Incorrect shared secret key length.");
        }

        byte[] cipherBytes = messageEncoder.decode(cipher);
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

        byte[] sharedKey = messageEncoder.decode(sharedSecretKey);

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

        byte[] sharedKey = messageEncoder.decode(sharedSecretKey);
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

    @Override
    public String cryptoBoxSealEasy(String message, Key publicKey) throws SodiumException {
        byte[] keyBytes = publicKey.getAsBytes();
        byte[] messageBytes = bytes(message);
        byte[] cipher = new byte[Box.SEALBYTES + messageBytes.length];

        if (!cryptoBoxSeal(cipher, messageBytes, messageBytes.length, keyBytes)) {
            throw new SodiumException("Could not encrypt message.");
        }
        return messageEncoder.encode(cipher);
    }

    @Override
    public String cryptoBoxSealOpenEasy(String cipherText, KeyPair keyPair) throws SodiumException {
        byte[] cipher = messageEncoder.decode(cipherText);
        byte[] message = new byte[cipher.length - Box.SEALBYTES];

        boolean res = cryptoBoxSealOpen(message,
                cipher,
                cipher.length,
                keyPair.getPublicKey().getAsBytes(),
                keyPair.getSecretKey().getAsBytes());
        if (!res) {
            throw new SodiumException("Could not decrypt your message.");
        }
        return str(message);
    }

    //// -------------------------------------------|
    //// CRYPTO SIGN
    //// -------------------------------------------|

    @Override
    public boolean cryptoSignInit(Sign.StateCryptoSign state) {
        return successful(getSodium().crypto_sign_init(state));
    }

    @Override
    public boolean cryptoSignUpdate(Sign.StateCryptoSign state, byte[] chunk, long chunkLength) {
        return successful(getSodium().crypto_sign_update(state, chunk, chunkLength));
    }

    @Override
    public boolean cryptoSignFinalCreate(Sign.StateCryptoSign state, byte[] sig, Pointer sigLen, byte[] sk) {
        return successful(getSodium().crypto_sign_final_create(state, sig, sigLen, sk));
    }

    @Override
    public boolean cryptoSignFinalVerify(Sign.StateCryptoSign state, byte[] sig, byte[] pk) {
        return successful(getSodium().crypto_sign_final_verify(state, sig, pk));
    }

    @Override
    public boolean cryptoSignKeypair(byte[] publicKey, byte[] secretKey) {
        return successful(getSodium().crypto_sign_keypair(publicKey, secretKey));
    }


    @Override
    public boolean cryptoSignSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        return successful(getSodium().crypto_sign_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoSign(byte[] signedMessage, byte[] message, long messageLen, byte[] secretKey) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_sign(signedMessage, (new PointerByReference(Pointer.NULL)).getPointer(), message, messageLen, secretKey));
    }

    @Override
    public boolean cryptoSignOpen(byte[] message, byte[] signedMessage, long signedMessageLen, byte[] publicKey) {
        if (signedMessageLen < 0 || signedMessageLen > signedMessage.length) {
            throw new IllegalArgumentException("signedMessageLen out of bounds: " + signedMessageLen);
        }
        return successful(getSodium().crypto_sign_open(message, (new PointerByReference(Pointer.NULL)).getPointer(), signedMessage, signedMessageLen, publicKey));
    }

    @Override
    public boolean cryptoSignDetached(byte[] signature, byte[] message, long messageLen, byte[] secretKey) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_sign_detached(signature, (new PointerByReference(Pointer.NULL)).getPointer(), message, messageLen, secretKey));
    }

    @Override
    public boolean cryptoSignVerifyDetached(byte[] signature, byte[] message, int messageLen, byte[] publicKey) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
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

    @Override
    public boolean cryptoSignEd25519SkToSeed(byte[] seed, byte[] ed) {
        return successful(getSodium().crypto_sign_ed25519_sk_to_seed(seed, ed));
    }

    @Override
    public boolean cryptoSignEd25519SkToPk(byte[] publicKey, byte[] ed) {
        return successful(getSodium().crypto_sign_ed25519_sk_to_pk(publicKey, ed));
    }

    // -- lazy

    @Override
    public KeyPair cryptoSignKeypair() throws SodiumException {
        byte[] publicKey = randomBytesBuf(Sign.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Sign.SECRETKEYBYTES);
        if (!cryptoSignKeypair(publicKey, secretKey)) {
            throw new SodiumException("Could not generate a signing keypair.");
        }
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    public KeyPair cryptoSignSeedKeypair(byte[] seed) throws SodiumException {
        byte[] publicKey = randomBytesBuf(Sign.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Sign.SECRETKEYBYTES);
        if (!cryptoSignSeedKeypair(publicKey, secretKey, seed)) {
            throw new SodiumException("Could not generate a signing keypair with a seed.");
        }
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey));
    }

    @Override
    public KeyPair cryptoSignSecretKeyPair(Key secretKey) throws SodiumException {
        byte[] publicKey = new byte[Sign.PUBLICKEYBYTES];
        byte[] secKeyBytes = secretKey.getAsBytes();
        if (!cryptoSignEd25519SkToPk(publicKey, secKeyBytes)) {
            throw new SodiumException("Could not extract public key.");
        }
        return new KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secKeyBytes));
    }

    @Override
    public String cryptoSign(String message, String secretKey) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] secretKeyBytes = messageEncoder.decode(secretKey);
        byte[] signedMessage = randomBytesBuf(Sign.BYTES + messageBytes.length);
        boolean res = cryptoSign(signedMessage, messageBytes, messageBytes.length, secretKeyBytes);

        if (!res) {
            throw new SodiumException("Could not sign your message.");
        }

        return messageEncoder.encode(signedMessage);
    }

    @Override
    public String cryptoSign(String message, Key secretKey) throws SodiumException {
        return cryptoSign(message, secretKey.getAsHexString());
    }

    @Override
    public String cryptoSignOpen(String signedMessage, Key publicKey) {
        byte[] signedMessageBytes = messageEncoder.decode(signedMessage);
        byte[] publicKeyBytes = publicKey.getAsBytes();

        byte[] messageBytes = randomBytesBuf(signedMessageBytes.length - Sign.BYTES);

        boolean res = cryptoSignOpen(
                messageBytes,
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
    public String cryptoSignDetached(String message, Key secretKey) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] skBytes = secretKey.getAsBytes();
        byte[] signatureBytes = new byte[Sign.BYTES];

        if (!cryptoSignDetached(signatureBytes, messageBytes, messageBytes.length, skBytes)) {
            throw new SodiumException("Could not create a signature for your message in detached mode.");
        }

        return messageEncoder.encode(signatureBytes);
    }

    @Override
    public boolean cryptoSignVerifyDetached(String signature, String message, Key publicKey) {
        byte[] messageBytes = bytes(message);
        byte[] pkBytes = publicKey.getAsBytes();
        byte[] signatureBytes = messageEncoder.decode(signature);

        return cryptoSignVerifyDetached(signatureBytes, messageBytes, messageBytes.length, pkBytes);
    }

    @Override
    public KeyPair convertKeyPairEd25519ToCurve25519(KeyPair ed25519KeyPair) throws SodiumException {
        byte[] edPkBytes = ed25519KeyPair.getPublicKey().getAsBytes();
        byte[] edSkBytes = ed25519KeyPair.getSecretKey().getAsBytes();

        byte[] curvePkBytes = new byte[Sign.CURVE25519_PUBLICKEYBYTES];
        byte[] curveSkBytes = new byte[Sign.CURVE25519_SECRETKEYBYTES];

        boolean pkSuccess = convertPublicKeyEd25519ToCurve25519(curvePkBytes, edPkBytes);
        boolean skSuccess = convertSecretKeyEd25519ToCurve25519(curveSkBytes, edSkBytes);

        if (!pkSuccess || !skSuccess) {
            throw new SodiumException("Could not convert this key pair.");
        }

        return new KeyPair(Key.fromBytes(curvePkBytes), Key.fromBytes(curveSkBytes));
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
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
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
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
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
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        if (additionalDataLen < 0 || additionalDataLen > additionalData.length) {
            throw new IllegalArgumentException("additionalDataLen out of bounds: " + additionalDataLen);
        }
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
        if (cipherLen < 0 || cipherLen > cipher.length) {
            throw new IllegalArgumentException("cipherLen out of bounds: " + cipherLen);
        }
        if (additionalDataLen < 0 || additionalDataLen > additionalData.length) {
            throw new IllegalArgumentException("additionalDataLen out of bounds: " + additionalDataLen);
        }
        return successful(getSodium().crypto_secretstream_xchacha20poly1305_pull(
                state, message, messageAddress, tag, cipher, cipherLen, additionalData, additionalDataLen
        ));
    }

    @Override
    public boolean cryptoSecretStreamPull(SecretStream.State state, byte[] message, byte[] tag, byte[] cipher, long cipherLen) {
        if (cipherLen < 0 || cipherLen > cipher.length) {
            throw new IllegalArgumentException("cipherLen out of bounds: " + cipherLen);
        }
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
    public Key cryptoSecretStreamKeygen() {
        byte[] key = randomBytesBuf(SecretStream.KEYBYTES);
        getSodium().crypto_secretstream_xchacha20poly1305_keygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public SecretStream.State cryptoSecretStreamInitPush(byte[] header, Key key) throws SodiumException {
        SecretStream.State state = new SecretStream.State.ByReference();
        if (!SecretStream.Checker.headerCheck(header.length)) {
            throw new SodiumException("Header of secret stream incorrect length.");
        }
        getSodium().crypto_secretstream_xchacha20poly1305_init_push(state, header, key.getAsBytes());
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

        return messageEncoder.encode(cipher);
    }

    @Override
    public SecretStream.State cryptoSecretStreamInitPull(byte[] header, Key key) throws SodiumException {
        SecretStream.State state = new SecretStream.State.ByReference();
        if (!SecretStream.Checker.headerCheck(header.length)) {
            throw new SodiumException("Header of secret stream incorrect length.");
        }

        int res = getSodium().crypto_secretstream_xchacha20poly1305_init_pull(state, header, key.getAsBytes());

        if (res != 0) {
            throw new SodiumException("Could not initialise a decryption state.");
        }

        return state;
    }

    @Override
    public String cryptoSecretStreamPull(SecretStream.State state, String cipher, byte[] tag) throws SodiumException {
        byte[] cipherBytes = messageEncoder.decode(cipher);
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
    //// STREAM
    //// -------------------------------------------|

    @Override
    public void cryptoStreamChaCha20Keygen(byte[] key) {
        getSodium().crypto_stream_chacha20_keygen(key);
    }

    @Override
    public boolean cryptoStreamChaCha20(byte[] c, long cLen, byte[] nonce, byte[] key) {
        if (cLen < 0 || cLen > c.length) {
            throw new IllegalArgumentException("cLen out of bounds: " + cLen);
        }
        return successful(getSodium().crypto_stream_chacha20(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamChaCha20Xor(byte[] cipher, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_stream_chacha20_xor(cipher, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamChacha20XorIc(byte[] cipher, byte[] message, long messageLen, byte[] nonce, long ic, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_stream_chacha20_xor_ic(cipher, message, messageLen, nonce, ic, key));
    }

    // Chacha20 Ietf

    @Override
    public void cryptoStreamChaCha20IetfKeygen(byte[] key) {
        getSodium().crypto_stream_chacha20_ietf_keygen(key);
    }

    @Override
    public boolean cryptoStreamChaCha20Ietf(byte[] c, long cLen, byte[] nonce, byte[] key) {
        if (cLen < 0 || cLen > c.length) {
            throw new IllegalArgumentException("cLen out of bounds: " + cLen);
        }
        return successful(getSodium().crypto_stream_chacha20_ietf(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamChaCha20IetfXor(byte[] cipher, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_stream_chacha20_ietf_xor(cipher, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamChacha20IetfXorIc(byte[] cipher, byte[] message, long messageLen, byte[] nonce, long ic, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_stream_chacha20_ietf_xor_ic(cipher, message, messageLen, nonce, ic, key));
    }

    // Salsa20

    @Override
    public void cryptoStreamSalsa20Keygen(byte[] key) {
        getSodium().crypto_stream_salsa20_keygen(key);
    }

    @Override
    public boolean cryptoStreamSalsa20(byte[] c, long cLen, byte[] nonce, byte[] key) {
        if (cLen < 0 || cLen > c.length) {
            throw new IllegalArgumentException("cLen out of bounds: " + cLen);
        }
        return successful(getSodium().crypto_stream_salsa20(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamSalsa20Xor(byte[] cipher, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_stream_salsa20_xor(cipher, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamSalsa20XorIc(byte[] cipher, byte[] message, long messageLen, byte[] nonce, long ic, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_stream_salsa20_xor_ic(cipher, message, messageLen, nonce, ic, key));
    }


    @Override
    public void cryptoStreamXSalsa20Keygen(byte[] key) {
        getSodium().crypto_stream_keygen(key);
    }

    @Override
    public boolean cryptoStreamXSalsa20(byte[] c, long cLen, byte[] nonce, byte[] key) {
        if (cLen < 0 || cLen > c.length) {
            throw new IllegalArgumentException("cLen out of bounds: " + cLen);
        }
        return successful(getSodium().crypto_stream(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamXSalsa20Xor(byte[] cipher, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        if (messageLen < 0 || messageLen > message.length) {
            throw new IllegalArgumentException("messageLen out of bounds: " + messageLen);
        }
        return successful(getSodium().crypto_stream_xor(cipher, message, messageLen, nonce, key));
    }

    // Lazy

    @Override
    public Key cryptoStreamKeygen(Stream.Method method) {
        if (method.equals(Stream.Method.CHACHA20)) {
            byte[] k = randomBytesBuf(Stream.CHACHA20_KEYBYTES);
            cryptoStreamChaCha20Keygen(k);
            return Key.fromBytes(k);
        } else if (method.equals(Stream.Method.CHACHA20_IETF)) {
            byte[] k = randomBytesBuf(Stream.CHACHA20_IETF_KEYBYTES);
            cryptoStreamChaCha20Keygen(k);
            return Key.fromBytes(k);
        } else if (method.equals(Stream.Method.SALSA20)) {
            byte[] k = randomBytesBuf(Stream.SALSA20_KEYBYTES);
            cryptoStreamSalsa20Keygen(k);
            return Key.fromBytes(k);
        } else {
            byte[] k = randomBytesBuf(Stream.XSALSA20_KEYBYTES);
            cryptoStreamXSalsa20Keygen(k);
            return Key.fromBytes(k);
        }
    }


    @Override
    public byte[] cryptoStream(byte[] nonce, Key key, Stream.Method method) {
        byte[] c = new byte[20];
        int cLen = c.length;
        if (method.equals(Stream.Method.CHACHA20)) {
            cryptoStreamChaCha20(c, cLen, nonce, key.getAsBytes());
        } else if (method.equals(Stream.Method.CHACHA20_IETF)) {
            cryptoStreamChaCha20Ietf(c, cLen, nonce, key.getAsBytes());
        } else if (method.equals(Stream.Method.SALSA20)) {
            cryptoStreamSalsa20(c, cLen, nonce, key.getAsBytes());
        } else {
            cryptoStreamXSalsa20(c, cLen, nonce, key.getAsBytes());
        }
        return c;
    }

    @Override
    public String cryptoStreamXor(String message, byte[] nonce, Key key, Stream.Method method) {
        byte[] mBytes = bytes(message);
        return messageEncoder.encode(cryptoStreamDefaultXor(mBytes, nonce, key, method));
    }

    @Override
    public String cryptoStreamXorDecrypt(String cipher, byte[] nonce, Key key, Stream.Method method) {
        return str(cryptoStreamDefaultXor(messageEncoder.decode(cipher), nonce, key, method));
    }


    @Override
    public String cryptoStreamXorIc(String message, byte[] nonce, long ic, Key key, Stream.Method method) {
        byte[] mBytes = bytes(message);
        return messageEncoder.encode(cryptoStreamDefaultXorIc(mBytes, nonce, ic, key, method));
    }

    @Override
    public String cryptoStreamXorIcDecrypt(String cipher, byte[] nonce, long ic, Key key, Stream.Method method) {
        byte[] cipherBytes = messageEncoder.decode(cipher);
        return str(cryptoStreamDefaultXorIc(cipherBytes, nonce, ic, key, method));
    }


    private byte[] cryptoStreamDefaultXor(byte[] messageBytes, byte[] nonce, Key key, Stream.Method method) {
        int mLen = messageBytes.length;
        byte[] cipher = new byte[mLen];
        if (method.equals(Stream.Method.CHACHA20)) {
            cryptoStreamChaCha20Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        } else if (method.equals(Stream.Method.CHACHA20_IETF)) {
            cryptoStreamChaCha20IetfXor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        } else if (method.equals(Stream.Method.SALSA20)) {
            cryptoStreamSalsa20Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        } else {
            cryptoStreamXSalsa20Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        }
        return cipher;
    }

    protected byte[] cryptoStreamDefaultXorIc(byte[] messageBytes, byte[] nonce, long ic, Key key, Stream.Method method) {
        int mLen = messageBytes.length;
        byte[] cipher = new byte[mLen];
        if (method.equals(Stream.Method.CHACHA20)) {
            cryptoStreamChacha20XorIc(cipher, messageBytes, mLen, nonce, ic, key.getAsBytes());
        } else if (method.equals(Stream.Method.CHACHA20_IETF)) {
            cryptoStreamChacha20IetfXorIc(cipher, messageBytes, mLen, nonce, ic, key.getAsBytes());
        } else if (method.equals(Stream.Method.SALSA20)) {
            cryptoStreamSalsa20XorIc(cipher, messageBytes, mLen, nonce, ic, key.getAsBytes());
        } else {
            // XSalsa20 has no IC so return the
            // one without the IC
            cryptoStreamXSalsa20Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        }
        return cipher;
    }


    //// -------------------------------------------|
    //// CRYPTO AUTH
    //// -------------------------------------------|

    @Override
    public boolean cryptoAuth(byte[] tag, byte[] in, long inLen, byte[] key) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth(tag, in, inLen, key));
    }

    @Override
    public boolean cryptoAuthVerify(byte[] tag, byte[] in, long inLen, byte[] key) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth_verify(tag, in, inLen, key));
    }

    @Override
    public void cryptoAuthKeygen(byte[] k) {
        getSodium().crypto_auth_keygen(k);
    }


    @Override
    public Key cryptoAuthKeygen() {
        byte[] key = randomBytesBuf(Auth.KEYBYTES);
        cryptoAuthKeygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public String cryptoAuth(String message, Key key) throws SodiumException {
        byte[] tag = randomBytesBuf(Auth.BYTES);
        byte[] messageBytes = bytes(message);
        byte[] keyBytes = key.getAsBytes();
        boolean res = cryptoAuth(tag, messageBytes, messageBytes.length, keyBytes);

        if (!res) {
            throw new SodiumException("Could not apply auth tag to your message.");
        }

        return messageEncoder.encode(tag);
    }

    @Override
    public boolean cryptoAuthVerify(String tag, String message, Key key) {
        byte[] tagToBytes = messageEncoder.decode(tag);
        byte[] messageBytes = bytes(message);
        byte[] keyBytes = key.getAsBytes();
        return cryptoAuthVerify(tagToBytes, messageBytes, messageBytes.length, keyBytes);
    }


    @Override
    public void cryptoAuthHMACSha256Keygen(byte[] key) {
        getSodium().crypto_auth_hmacsha256_keygen(key);
    }

    @Override
    public boolean cryptoAuthHMACSha256(byte[] out, byte[] in, long inLen, byte[] k) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth_hmacsha256(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha256Verify(byte[] h, byte[] in, long inLen, byte[] k) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth_hmacsha256_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha256Init(Auth.StateHMAC256 state, byte[] key, int keyLen) {
        if (keyLen < 0 || keyLen > key.length) {
            throw new IllegalArgumentException("keyLen out of bounds: " + keyLen);
        }
        return successful(getSodium().crypto_auth_hmacsha256_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha256Update(Auth.StateHMAC256 state, byte[] in, long inLen) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
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
    public boolean cryptoAuthHMACSha512(byte[] out, byte[] in, long inLen, byte[] k) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth_hmacsha512(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512Verify(byte[] h, byte[] in, long inLen, byte[] k) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth_hmacsha512_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512Init(Auth.StateHMAC512 state, byte[] key, int keyLen) {
        if (keyLen < 0 || keyLen > key.length) {
            throw new IllegalArgumentException("keyLen out of bounds: " + keyLen);
        }
        return successful(getSodium().crypto_auth_hmacsha512_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512Update(Auth.StateHMAC512 state, byte[] in, long inLen) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
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
    public boolean cryptoAuthHMACSha512256(byte[] out, byte[] in, long inLen, byte[] k) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth_hmacsha512256(out, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Verify(byte[] h, byte[] in, long inLen, byte[] k) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth_hmacsha512256_verify(h, in, inLen, k));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Init(Auth.StateHMAC512256 state, byte[] key, int keyLen) {
        if (keyLen < 0 || keyLen > key.length) {
            throw new IllegalArgumentException("keyLen out of bounds: " + keyLen);
        }
        return successful(getSodium().crypto_auth_hmacsha512256_init(state, key, keyLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Update(Auth.StateHMAC512256 state, byte[] in, long inLen) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_auth_hmacsha512256_update(state, in, inLen));
    }

    @Override
    public boolean cryptoAuthHMACSha512256Final(Auth.StateHMAC512256 state, byte[] out) {
        return successful(getSodium().crypto_auth_hmacsha512256_final(state, out));
    }


    @Override
    public Key cryptoAuthHMACShaKeygen(Auth.Type type) {
        if (type.equals(Auth.Type.SHA256)) {
            byte[] k = new byte[Auth.HMACSHA256_KEYBYTES];
            cryptoAuthHMACSha256Keygen(k);
            return Key.fromBytes(k);
        } else if (type.equals(Auth.Type.SHA512)) {
            byte[] k = new byte[Auth.HMACSHA512_KEYBYTES];
            cryptoAuthHMACSha512Keygen(k);
            return Key.fromBytes(k);
        } else {
            byte[] k = new byte[Auth.HMACSHA512256_KEYBYTES];
            cryptoAuthHMACSha512256Keygen(k);
            return Key.fromBytes(k);
        }
    }

    @Override
    public String cryptoAuthHMACSha(Auth.Type type, String in, Key key) {
        byte[] inBytes = bytes(in);
        byte[] keyBytes = key.getAsBytes();
        long inByteLen = inBytes.length;
        if (type.equals(Auth.Type.SHA256)) {
            byte[] out = new byte[Auth.HMACSHA256_BYTES];
            cryptoAuthHMACSha256(out, inBytes, inByteLen, keyBytes);
            return messageEncoder.encode(out);
        } else if (type.equals(Auth.Type.SHA512)) {
            byte[] out = new byte[Auth.HMACSHA512_BYTES];
            cryptoAuthHMACSha512(out, inBytes, inByteLen, keyBytes);
            return messageEncoder.encode(out);
        } else {
            byte[] out = new byte[Auth.HMACSHA512256_BYTES];
            cryptoAuthHMACSha512256(out, inBytes, inByteLen, keyBytes);
            return messageEncoder.encode(out);
        }
    }

    @Override
    public boolean cryptoAuthHMACShaVerify(Auth.Type type, String h, String in, Key key) {
        byte[] authBytes = messageEncoder.decode(h);
        byte[] inBytes = bytes(in);
        byte[] keyBytes = key.getAsBytes();
        long inByteLen = inBytes.length;
        if (type.equals(Auth.Type.SHA256)) {
            return cryptoAuthHMACSha256Verify(authBytes, inBytes, inByteLen, keyBytes);
        } else if (type.equals(Auth.Type.SHA512)) {
            return cryptoAuthHMACSha512Verify(authBytes, inBytes, inByteLen, keyBytes);
        } else {
            return cryptoAuthHMACSha512256Verify(authBytes, inBytes, inByteLen, keyBytes);
        }
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC256 state, Key key) {
        byte[] keyBytes = key.getAsBytes();
        return cryptoAuthHMACSha256Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC256 state, String in) {
        byte[] inBytes = bytes(in);
        long inByteLen = inBytes.length;
        return cryptoAuthHMACSha256Update(state, inBytes, inByteLen);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC256 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA256_BYTES];
        boolean res = cryptoAuthHMACSha256Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise SHA Hash.");
        }
        return messageEncoder.encode(out);
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC512 state, Key key) {
        byte[] keyBytes = key.getAsBytes();
        return cryptoAuthHMACSha512Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC512 state, String in) {
        byte[] inBytes = bytes(in);
        long inByteLen = inBytes.length;
        return cryptoAuthHMACSha512Update(state, inBytes, inByteLen);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC512 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA512_BYTES];
        boolean res = cryptoAuthHMACSha512Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise HMAC Sha 512.");
        }
        return messageEncoder.encode(out);
    }

    @Override
    public boolean cryptoAuthHMACShaInit(Auth.StateHMAC512256 state, Key key) {
        byte[] keyBytes = key.getAsBytes();
        return cryptoAuthHMACSha512256Init(state, keyBytes, keyBytes.length);
    }

    @Override
    public boolean cryptoAuthHMACShaUpdate(Auth.StateHMAC512256 state, String in) {
        byte[] inBytes = bytes(in);
        long inByteLen = inBytes.length;
        return cryptoAuthHMACSha512256Update(state, inBytes, inByteLen);
    }

    @Override
    public String cryptoAuthHMACShaFinal(Auth.StateHMAC512256 state) throws SodiumException {
        byte[] out = new byte[Auth.HMACSHA512256_BYTES];
        boolean res = cryptoAuthHMACSha512256Final(state, out);
        if (!res) {
            throw new SodiumException("Could not finalise HMAC Sha 512256.");
        }
        return messageEncoder.encode(out);
    }

    //// -------------------------------------------|
    //// SHORT HASH
    //// -------------------------------------------|

    @Override
    public boolean cryptoShortHash(byte[] out, byte[] in, long inLen, byte[] key) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        return successful(getSodium().crypto_shorthash(out, in, inLen, key));
    }

    @Override
    public void cryptoShortHashKeygen(byte[] k) {
        getSodium().crypto_shorthash_keygen(k);
    }

    @Override
    public String cryptoShortHash(String in, Key key) throws SodiumException {
        byte[] inBytes = hexToBytes(in);
        byte[] keyBytes = key.getAsBytes();
        byte[] out = randomBytesBuf(ShortHash.BYTES);
        if (getSodium().crypto_shorthash(out, inBytes, inBytes.length, keyBytes) != 0) {
            throw new SodiumException("Failed short-input hashing.");
        }
        return sodiumBin2Hex(out);
    }

    @Override
    public Key cryptoShortHashKeygen() {
        byte[] key = randomBytesBuf(ShortHash.SIPHASH24_KEYBYTES);
        getSodium().crypto_shorthash_keygen(key);
        return Key.fromBytes(key);
    }


    //// -------------------------------------------|
    //// GENERIC HASH
    //// -------------------------------------------|

    @Override
    public boolean cryptoGenericHash(byte[] out, int outLen, byte[] in, long inLen, byte[] key, int keyLen) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        if (outLen < 0 || outLen > out.length) {
            throw new IllegalArgumentException("outLen out of bounds: " + outLen);
        }
        return successful(getSodium().crypto_generichash(out, outLen, in, inLen, key, keyLen));
    }

    @Override
    public boolean cryptoGenericHash(byte[] out, int outLen, byte[] in, long inLen) {
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
        if (outLen < 0 || outLen > out.length) {
            throw new IllegalArgumentException("outLen out of bounds: " + outLen);
        }
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
        if (inLen < 0 || inLen > in.length) {
            throw new IllegalArgumentException("inLen out of bounds: " + inLen);
        }
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
    public Key cryptoGenericHashKeygen() {
        byte[] key = randomBytesBuf(GenericHash.KEYBYTES);
        cryptoGenericHashKeygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public Key cryptoGenericHashKeygen(int size) throws SodiumException {
        byte[] key = randomBytesBuf(size);
        cryptoGenericHashKeygen(key);
        return Key.fromBytes(key);
    }

    @Override
    public String cryptoGenericHash(String in, Key key) throws SodiumException {
        byte[] message = bytes(in);
        byte[] keyBytes = key.getAsBytes();

        byte[] hash = randomBytesBuf(GenericHash.BYTES);
        boolean res = cryptoGenericHash(hash, hash.length, message, message.length, keyBytes, keyBytes.length);

        if (!res) {
            throw new SodiumException("Could not hash the message.");
        }

        return messageEncoder.encode(hash);
    }

    @Override
    public String cryptoGenericHash(String in) throws SodiumException {
        byte[] message = bytes(in);
        byte[] hash = randomBytesBuf(GenericHash.BYTES);
        boolean res = cryptoGenericHash(hash, hash.length, message, message.length, null, 0);

        if (!res) {
            throw new SodiumException("Could not hash the message.");
        }

        return messageEncoder.encode(hash);
    }

    @Override
    public boolean cryptoGenericHashInit(byte[] state, Key key, int outLen) {
        byte[] keyBytes = key.getAsBytes();
        return getSodium().crypto_generichash_init(state, keyBytes, keyBytes.length, outLen) == 0;
    }

    @Override
    public boolean cryptoGenericHashUpdate(byte[] state, String in) {
        byte[] inBytes = bytes(in);
        return getSodium().crypto_generichash_update(state, inBytes, inBytes.length) == 0;
    }

    @Override
    public String cryptoGenericHashFinal(byte[] state, int outLen) throws SodiumException {
        byte[] hash = new byte[outLen];
        boolean res = getSodium().crypto_generichash_final(state, hash, hash.length) == 0;
        if (!res) {
            throw new SodiumException("Could not finalise the hashing process.");
        }
        return messageEncoder.encode(hash);
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
        if (mLen < 0 || mLen > m.length) {
            throw new IllegalArgumentException("mLen out of bounds: " + mLen);
        }
        if (adLen < 0 || adLen > ad.length) {
            throw new IllegalArgumentException("adLen out of bounds: " + adLen);
        }
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

    @Override
    public boolean cryptoAeadAES256GCMIsAvailable() {
        return getSodium().crypto_aead_aes256gcm_is_available() == 1;
    }


    // -- lazy

    @Override
    public Key keygen(AEAD.Method method) {
        switch (method) {
            case CHACHA20_POLY1305:
                byte[] key = randomBytesBuf(AEAD.CHACHA20POLY1305_KEYBYTES);
                cryptoAeadChaCha20Poly1305Keygen(key);
                return Key.fromBytes(key);
            case CHACHA20_POLY1305_IETF:
                byte[] key2 = randomBytesBuf(AEAD.CHACHA20POLY1305_IETF_KEYBYTES);
                cryptoAeadChaCha20Poly1305IetfKeygen(key2);
                return Key.fromBytes(key2);
            case XCHACHA20_POLY1305_IETF:
                byte[] key3 = randomBytesBuf(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES);
                cryptoAeadXChaCha20Poly1305IetfKeygen(key3);
                return Key.fromBytes(key3);
            case AES256GCM:
                byte[] key4 = randomBytesBuf(AEAD.AES256GCM_KEYBYTES);
                cryptoAeadAES256GCMKeygen(key4);
                return Key.fromBytes(key4);
        }
        return null;
    }

    @Override
    public String encrypt(String m, String additionalData, byte[] nPub, Key k, AEAD.Method method) {
        return encrypt(m, additionalData, null, nPub, k, method);
    }

    @Override
    public String encrypt(String m, String additionalData, byte[] nSec, byte[] nPub, Key k, AEAD.Method method) {
        byte[] messageBytes = bytes(m);
        byte[] additionalDataBytes = additionalData == null ? new byte[0] : bytes(additionalData);
        long additionalBytesLen = additionalData == null ? 0L : additionalDataBytes.length;
        byte[] keyBytes = k.getAsBytes();

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
            return messageEncoder.encode(cipherBytes);
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
            return messageEncoder.encode(cipherBytes);
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
            return messageEncoder.encode(cipherBytes3);
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
            return messageEncoder.encode(cipherBytes);
        }
    }


    @Override
    public String decrypt(String cipher, String additionalData, byte[] nPub, Key k, AEAD.Method method) throws AEADBadTagException {
        return decrypt(cipher, additionalData, null, nPub, k, method);
    }

    @Override
    public String decrypt(String cipher, String additionalData, byte[] nSec, byte[] nPub, Key k, AEAD.Method method) throws AEADBadTagException {
        byte[] cipherBytes = messageEncoder.decode(cipher);
        byte[] additionalDataBytes = additionalData == null ? new byte[0] : bytes(additionalData);
        long additionalBytesLen = additionalData == null ? 0L : additionalDataBytes.length;
        byte[] keyBytes = k.getAsBytes();

        if (method.equals(AEAD.Method.CHACHA20_POLY1305)) {
            byte[] messageBytes = new byte[cipherBytes.length - AEAD.CHACHA20POLY1305_ABYTES];
            if (!cryptoAeadChaCha20Poly1305Decrypt(
                    messageBytes,
                    null,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            )) {
                throw new AEADBadTagException();
            }
            return str(messageBytes);
        } else if (method.equals(AEAD.Method.CHACHA20_POLY1305_IETF)) {
            byte[] messageBytes = new byte[cipherBytes.length - AEAD.CHACHA20POLY1305_IETF_ABYTES];
            if (!cryptoAeadChaCha20Poly1305IetfDecrypt(
                    messageBytes,
                    null,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            )) {
                throw new AEADBadTagException();
            }
            return str(messageBytes);
        } else if (method.equals(AEAD.Method.XCHACHA20_POLY1305_IETF)) {
            byte[] messageBytes = new byte[cipherBytes.length - AEAD.XCHACHA20POLY1305_IETF_ABYTES];
            if (!cryptoAeadXChaCha20Poly1305IetfDecrypt(
                    messageBytes,
                    null,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            )) {
                throw new AEADBadTagException();
            }
            return str(messageBytes);
        } else {
            byte[] messageBytes = new byte[cipherBytes.length - AEAD.AES256GCM_ABYTES];
            if (!cryptoAeadAES256GCMDecrypt(
                    messageBytes,
                    null,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            )) {
                throw new AEADBadTagException();
            }
            return str(messageBytes);
        }
    }

    @Override
    public DetachedEncrypt encryptDetached(String m, String additionalData, byte[] nSec, byte[] nPub, Key k, AEAD.Method method) {
        byte[] messageBytes = bytes(m);
        byte[] additionalDataBytes = additionalData == null ? new byte[0] : bytes(additionalData);
        long additionalBytesLen = additionalData == null ? 0L : additionalDataBytes.length;
        byte[] keyBytes = k.getAsBytes();
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
    public DetachedDecrypt decryptDetached(DetachedEncrypt detachedEncrypt, String additionalData, byte[] nSec, byte[] nPub, Key k, AEAD.Method method) throws AEADBadTagException {
        byte[] cipherBytes = detachedEncrypt.getCipher();
        byte[] additionalDataBytes = additionalData == null ? new byte[0] : bytes(additionalData);
        long additionalBytesLen = additionalData == null ? 0L : additionalDataBytes.length;
        byte[] keyBytes = k.getAsBytes();
        byte[] messageBytes = new byte[cipherBytes.length];
        byte[] macBytes = detachedEncrypt.getMac();

        if (method.equals(AEAD.Method.CHACHA20_POLY1305)) {
            if (!cryptoAeadChaCha20Poly1305DecryptDetached(
                    messageBytes,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    macBytes,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            )) {
                throw new AEADBadTagException();
            }
            return new DetachedDecrypt(messageBytes, macBytes, charset);
        } else if (method.equals(AEAD.Method.CHACHA20_POLY1305_IETF)) {
            if (!cryptoAeadChaCha20Poly1305IetfDecryptDetached(
                    messageBytes,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    macBytes,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            )) {
                throw new AEADBadTagException();
            }
            return new DetachedDecrypt(messageBytes, macBytes, charset);
        } else if (method.equals(AEAD.Method.XCHACHA20_POLY1305_IETF)) {
            if (!cryptoAeadXChaCha20Poly1305IetfDecryptDetached(
                    messageBytes,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    macBytes,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            )) {
                throw new AEADBadTagException();
            }
            return new DetachedDecrypt(messageBytes, macBytes, charset);
        } else {
            if (!cryptoAeadAES256GCMDecryptDetached(
                    messageBytes,
                    nSec,
                    cipherBytes,
                    cipherBytes.length,
                    macBytes,
                    additionalDataBytes,
                    additionalBytesLen,
                    nPub,
                    keyBytes
            )) {
                throw new AEADBadTagException();
            }
            return new DetachedDecrypt(messageBytes, macBytes, charset);
        }
    }


    //// -------------------------------------------|
    //// Ristretto255
    //// -------------------------------------------|

    @Override
    public boolean cryptoCoreRistretto255IsValidPoint(byte[] point) {
        return point.length == Ristretto255.RISTRETTO255_BYTES
                   && getSodium().crypto_core_ristretto255_is_valid_point(point) == 1;
    }

    @Override
    public void cryptoCoreRistretto255Random(byte[] point) {
        Checker.ensurePointFits(point);

        getSodium().crypto_core_ristretto255_random(point);
    }

    @Override
    public boolean cryptoCoreRistretto255FromHash(byte[] point, byte[] hash) {
        Checker.ensurePointFits(point);
        Checker.checkHash(hash);

        return successful(getSodium().crypto_core_ristretto255_from_hash(point, hash));
    }

    @Override
    public boolean cryptoScalarmultRistretto255(byte[] result, byte[] n, byte[] point) {
        Checker.ensurePointFits(result);
        Checker.checkPoint(point);
        Checker.checkScalar(n);

        return successful(getSodium().crypto_scalarmult_ristretto255(result, n, point));
    }

    @Override
    public boolean cryptoScalarmultRistretto255Base(byte[] result, byte[] n) {
        Checker.ensurePointFits(result);
        Checker.checkScalar(n);

        return successful(getSodium().crypto_scalarmult_ristretto255_base(result, n));
    }

    @Override
    public boolean cryptoCoreRistretto255Add(byte[] result, byte[] p, byte[] q) {
        Checker.ensurePointFits(result);
        Checker.checkPoint(p);
        Checker.checkPoint(q);

        return successful(getSodium().crypto_core_ristretto255_add(result, p, q));
    }

    @Override
    public boolean cryptoCoreRistretto255Sub(byte[] result, byte[] p, byte[] q) {
        Checker.ensurePointFits(result);
        Checker.checkPoint(p);
        Checker.checkPoint(q);

        return successful(getSodium().crypto_core_ristretto255_sub(result, p, q));
    }

    @Override
    public void cryptoCoreRistretto255ScalarRandom(byte[] scalar) {
        Checker.ensureScalarFits(scalar);

        getSodium().crypto_core_ristretto255_scalar_random(scalar);
    }

    @Override
    public void cryptoCoreRistretto255ScalarReduce(byte[] result, byte[] scalar) {
        Checker.ensureScalarFits(result);
        Checker.checkNonReducedScalar(scalar);

        getSodium().crypto_core_ristretto255_scalar_reduce(result, scalar);
    }

    @Override
    public boolean cryptoCoreRistretto255ScalarInvert(byte[] result, byte[] scalar) {
        Checker.ensureScalarFits(result);
        Checker.checkScalar(scalar);

        return successful(getSodium().crypto_core_ristretto255_scalar_invert(result, scalar));
    }

    @Override
    public void cryptoCoreRistretto255ScalarNegate(byte[] result, byte[] scalar) {
        Checker.ensureScalarFits(result);
        Checker.checkScalar(scalar);

        getSodium().crypto_core_ristretto255_scalar_negate(result, scalar);
    }

    @Override
    public void cryptoCoreRistretto255ScalarComplement(byte[] result, byte[] scalar) {
        Checker.ensureScalarFits(result);
        Checker.checkScalar(scalar);

        getSodium().crypto_core_ristretto255_scalar_complement(result, scalar);
    }

    @Override
    public void cryptoCoreRistretto255ScalarAdd(byte[] result, byte[] x, byte[] y) {
        Checker.ensureScalarFits(result);
        Checker.checkScalar(x);
        Checker.checkScalar(y);

        getSodium().crypto_core_ristretto255_scalar_add(result, x, y);
    }

    @Override
    public void cryptoCoreRistretto255ScalarSub(byte[] result, byte[] x, byte[] y) {
        Checker.ensureScalarFits(result);
        Checker.checkScalar(x);
        Checker.checkScalar(y);

        getSodium().crypto_core_ristretto255_scalar_sub(result, x, y);
    }

    @Override
    public void cryptoCoreRistretto255ScalarMul(byte[] result, byte[] x, byte[] y) {
        Checker.ensureScalarFits(result);
        Checker.checkScalar(x);
        Checker.checkScalar(y);

        getSodium().crypto_core_ristretto255_scalar_mul(result, x, y);
    }


    // -- lazy

    @Override
    public boolean cryptoCoreRistretto255IsValidPoint(String point) {
        if (point == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        return cryptoCoreRistretto255IsValidPoint(toBin(point));
    }

    @Override
    public RistrettoPoint cryptoCoreRistretto255Random() {
        byte[] point = Ristretto255.pointBuffer();
        cryptoCoreRistretto255Random(point);

        return RistrettoPoint.fromBytes(this, point);
    }


    @Override
    public RistrettoPoint cryptoCoreRistretto255FromHash(byte[] hash) throws SodiumException {
        byte[] point = Ristretto255.pointBuffer();

        if (!cryptoCoreRistretto255FromHash(point, hash)) {
            throw new SodiumException("Conversion from hash to Ristretto point failed");
        }

        return RistrettoPoint.fromBytes(this, point);
    }

    @Override
    public RistrettoPoint cryptoScalarmultRistretto255(byte[] n, RistrettoPoint point)
        throws SodiumException {

        byte[] result = Ristretto255.pointBuffer();

        if (!cryptoScalarmultRistretto255(result, n, point.toBytes())) {
            throw new SodiumException(
                "Scalar multiplication failed. The resulting point was the identity element.");
        }

        return RistrettoPoint.fromBytes(this, result);
    }

    @Override
    public RistrettoPoint cryptoScalarmultRistretto255Base(byte[] n) throws SodiumException {
        byte[] result = Ristretto255.pointBuffer();

        if (!cryptoScalarmultRistretto255Base(result, n)) {
            throw new SodiumException(
                "Scalar multiplication failed. n was 0.");
        }

        return RistrettoPoint.fromBytes(this, result);
    }

    @Override
    public RistrettoPoint cryptoCoreRistretto255Add(RistrettoPoint p, RistrettoPoint q)
        throws SodiumException {
        if (p == null || q == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        byte[] result = Ristretto255.pointBuffer();
        if (!cryptoCoreRistretto255Add(result, p.toBytes(), q.toBytes())) {
            throw new SodiumException("Either p or q was not a valid point.");
        }

        return RistrettoPoint.fromBytes(this, result);
    }

    @Override
    public RistrettoPoint cryptoCoreRistretto255Sub(RistrettoPoint p, RistrettoPoint q)
        throws SodiumException {

        if (p == null || q == null) {
            throw new IllegalArgumentException("null arguments are invalid");
        }

        byte[] result = Ristretto255.pointBuffer();
        if (!cryptoCoreRistretto255Sub(result, p.toBytes(), q.toBytes())) {
            throw new SodiumException("Either p or q was not a valid point.");
        }

        return RistrettoPoint.fromBytes(this, result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarRandom() {
        byte[] scalar = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarRandom(scalar);

        return Ristretto255.bytesToScalar(scalar);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarReduce(byte[] scalar) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarReduce(result, scalar);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarInvert(byte[] scalar) throws SodiumException {
        byte[] result = Ristretto255.scalarBuffer();

        if (!cryptoCoreRistretto255ScalarInvert(result, scalar)) {
            throw new SodiumException("Scalar inversion failed. Did you pass 0?");
        }

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarNegate(byte[] scalar) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarNegate(result, scalar);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarComplement(byte[] scalar) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarComplement(result, scalar);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, byte[] y) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarAdd(result, x, y);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, byte[] y) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarSub(result, x, y);

        return Ristretto255.bytesToScalar(result);
    }

    @Override
    public BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, byte[] y) {
        byte[] result = Ristretto255.scalarBuffer();
        cryptoCoreRistretto255ScalarMul(result, x, y);

        return Ristretto255.bytesToScalar(result);
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
    public static void main(String[] args) throws SodiumException {

    }


}
