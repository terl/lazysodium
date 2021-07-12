package com.goterl.lazysodium.interfaces;

import static com.goterl.lazysodium.LazySodium.toBin;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.exceptions.SodiumException;
import java.math.BigInteger;
import java.util.Arrays;

public interface Ristretto255 {

    int RISTRETTO255_BYTES = 32;
    int RISTRETTO255_HASH_BYTES = 64;
    int RISTRETTO255_SCALAR_BYTES = 32;
    int RISTRETTO255_NON_REDUCED_SCALAR_BYTES = 64;
    BigInteger RISTRETTO255_L = BigInteger.valueOf(2).pow(252).add(
        new BigInteger("27742317777372353535851937790883648493", 10));

    static byte[] scalarToBytes(BigInteger n) {
        return scalarToBytes(n, true);
    }

    static byte[] scalarToBytes(BigInteger n, boolean reduced) {
        byte[] bytes = n.toByteArray();
        int expectedCount =
            reduced ? RISTRETTO255_SCALAR_BYTES : RISTRETTO255_NON_REDUCED_SCALAR_BYTES;

        if (bytes.length > expectedCount) {
            throw new IllegalArgumentException(
                "The scalar value is too big to be represented in " + expectedCount + " bytes");
        }

        // Convert big-endian to little-endian
        byte[] temp = new byte[expectedCount];

        for (int i = 0; i < bytes.length; ++i) {
            temp[i] = bytes[bytes.length - i - 1];
        }

        bytes = temp;

        return bytes;
    }

    static BigInteger bytesToScalar(byte[] bytes) {
        byte[] temp = new byte[bytes.length];

        // Convert little-endian to big-endian
        for (int i = 0; i < bytes.length; ++i) {
            temp[bytes.length - i - 1] = bytes[i];
        }

        return new BigInteger(temp);
    }

    static byte[] pointBuffer() {
        return new byte[RISTRETTO255_BYTES];
    }

    static byte[] scalarBuffer() {
        return new byte[RISTRETTO255_SCALAR_BYTES];
    }

    interface Native {

        /**
         * Returns whether the passed bytes represent a valid Ristretto255 point.
         *
         * @param point the point to check, should be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @return true if valid
         */
        boolean cryptoCoreRistretto255IsValidPoint(byte[] point);

        /**
         * Chooses a random Ristretto255 point and puts its representation to {@code point}
         *
         * @param point the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         */
        void cryptoCoreRistretto255Random(byte[] point);

        /**
         * Maps a {@link Ristretto255#RISTRETTO255_HASH_BYTES} bytes hash to a Ristretto255 point
         * and puts its representation to {@code point}.
         *
         * @param point the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param hash  the hash, must be {@link Ristretto255#RISTRETTO255_HASH_BYTES} bytes
         * @return true if successful
         */
        boolean cryptoCoreRistretto255FromHash(byte[] point, byte[] hash);

        /**
         * Multiplies the given Ristretto255 {@code point} by the scalar {@code n} and puts the
         * representation of the result into {@code result}.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param n      the scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param point  the Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @return true if successful
         */
        boolean cryptoScalarmultRistretto255(byte[] result, byte[] n, byte[] point);

        /**
         * Multiplies the Ristretto255 base point by the scalar {@code n} and puts the
         * representation of the result into {@code result}.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param n      the scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return true if successful
         */
        boolean cryptoScalarmultRistretto255Base(byte[] result, byte[] n);

        /**
         * Adds two given Ristretto255 points {@code p} and {@code q} and puts the representation of
         * the result into {@code result}.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param p      the first Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @param q      the second Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @return true if successful
         */
        boolean cryptoCoreRistretto255Add(byte[] result, byte[] p, byte[] q);

        /**
         * Subtracts two given Ristretto255 points {@code p} and {@code q} and puts the
         * representation of the result into {@code result}.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param p      the first Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @param q      the second Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @return true if successful
         */
        boolean cryptoCoreRistretto255Sub(byte[] result, byte[] p, byte[] q);

        /**
         * Creates a random scalar value in {@code [0, l[} with {@code L} being the order of the
         * Ristretto255 group.
         *
         * @param scalar the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarRandom(byte[] scalar);

        /**
         * Reduces a possibly larger scalar value to {@code [0, l[} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param scalar the scalar to reduce, must be {@link Ristretto255#RISTRETTO255_NON_REDUCED_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarReduce(byte[] result, byte[] scalar);

        /**
         * Calculates the multiplicative inverse of the given scalar value.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param scalar the scalar to invert, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @return true if successful
         */
        boolean cryptoCoreRistretto255ScalarInvert(byte[] result, byte[] scalar);

        /**
         * Calculates the additive inverse of the given scalar value.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param scalar the scalar to negate, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarNegate(byte[] result, byte[] scalar);

        /**
         * Calculates the result R for the given scalar value such that {@code R + scalar = 1 (mod
         * L)} with {@code L} being the order of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param scalar the scalar to complement, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarComplement(byte[] result, byte[] scalar);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param x      the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param y      the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarAdd(byte[] result, byte[] x, byte[] y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param x      the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param y      the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarSub(byte[] result, byte[] x, byte[] y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param x      the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param y      the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarMul(byte[] result, byte[] x, byte[] y);
    }

    interface Lazy {

        /**
         * Returns whether the passed hexadecimal string represents a valid Ristretto255 point.
         *
         * @param point the point to check
         * @return true if valid
         */
        boolean cryptoCoreRistretto255IsValidPoint(String point);

        /**
         * Chooses a random Ristretto255 point and returns it.
         *
         * @return a random Ristretto255 point
         */
        RistrettoPoint cryptoCoreRistretto255Random();

        /**
         * Maps a {@link Ristretto255#RISTRETTO255_HASH_BYTES} bytes hash in hexadecimal notation.
         *
         * @param hash the hash in hexadecimal notation
         * @return the corresponding Ristretto255 point
         */
        default RistrettoPoint cryptoCoreRistretto255FromHash(String hash) throws SodiumException {
            if (hash == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255FromHash(toBin(hash));
        }

        /**
         * Maps a {@link Ristretto255#RISTRETTO255_HASH_BYTES} bytes hash to a Ristretto255 point.
         *
         * @param hash the hash, must be {@link Ristretto255#RISTRETTO255_HASH_BYTES}
         * @return the corresponding Ristretto255 point
         */
        RistrettoPoint cryptoCoreRistretto255FromHash(byte[] hash) throws SodiumException;

        /**
         * Multiplies the given Ristretto255 {@code point} by the scalar {@code n} and returns the
         * resulting point.
         *
         * @param n     the scalar
         * @param point the Ristretto255 point in hexadecimal notation
         * @return the result
         */
        default RistrettoPoint cryptoScalarmultRistretto255(BigInteger n, RistrettoPoint point)
            throws SodiumException {
            if (n == null || point == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoScalarmultRistretto255(scalarToBytes(n), point);
        }

        /**
         * Multiplies the given Ristretto255 {@code point} by the scalar {@code n} and returns the
         * resulting point.
         *
         * @param nHex  the scalar in hexadecimal notation, in little-endian encoding
         * @param point the Ristretto255 point in hexadecimal notation
         * @return the result
         */
        default RistrettoPoint cryptoScalarmultRistretto255(String nHex, RistrettoPoint point)
            throws SodiumException {
            if (nHex == null || point == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoScalarmultRistretto255(toBin(nHex), point);
        }

        /**
         * Multiplies the given Ristretto255 {@code point} by the scalar {@code n} and returns the
         * resulting point.
         *
         * @param n     the scalar, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes, in
         *              little-endian encoding
         * @param point the Ristretto255 point in hexadecimal notation
         * @return the result
         */
        RistrettoPoint cryptoScalarmultRistretto255(byte[] n, RistrettoPoint point)
            throws SodiumException;

        /**
         * Multiplies the Ristretto255 base point by the scalar {@code n} and returns the result.
         *
         * @param n the scalar
         * @return the result
         */
        default RistrettoPoint cryptoScalarmultRistretto255Base(BigInteger n)
            throws SodiumException {
            if (n == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }
            return cryptoScalarmultRistretto255Base(scalarToBytes(n));
        }

        /**
         * Multiplies the Ristretto255 base point by the scalar {@code n} and returns the result.
         *
         * @param nHex the scalar in hexadecimal notation, in little-endian encoding
         * @return the result
         */
        default RistrettoPoint cryptoScalarmultRistretto255Base(String nHex)
            throws SodiumException {
            if (nHex == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoScalarmultRistretto255Base(toBin(nHex));
        }

        /**
         * Multiplies the Ristretto255 base point by the scalar {@code n} and returns the result.
         *
         * @param n the scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes, in
         *          little-endian encoding
         * @return the result
         */
        RistrettoPoint cryptoScalarmultRistretto255Base(byte[] n) throws SodiumException;

        /**
         * Adds two given Ristretto255 points {@code p} and {@code q} and returns the result.
         *
         * @param p the first Ristretto255 point
         * @param q the second Ristretto255 point
         * @return the sum
         */
        RistrettoPoint cryptoCoreRistretto255Add(RistrettoPoint p, RistrettoPoint q)
            throws SodiumException;

        /**
         * Subtracts two given Ristretto255 points {@code p} and {@code q} and returns the result.
         *
         * @param p the first Ristretto255 point
         * @param q the second Ristretto255 point
         * @return the difference
         */
        RistrettoPoint cryptoCoreRistretto255Sub(RistrettoPoint p, RistrettoPoint q)
            throws SodiumException;

        /**
         * Creates a random scalar value in {@code [0, l[} with {@code L} being the order of the
         * Ristretto255 group.
         *
         * @return the random scalar value
         */
        BigInteger cryptoCoreRistretto255ScalarRandom();

        /**
         * Reduces a possibly larger scalar value to {@code [0, l[} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param scalar the scalar to reduce
         * @return the reduced scalar
         */
        default BigInteger cryptoCoreRistretto255ScalarReduce(BigInteger scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarReduce(scalarToBytes(scalar, false));
        }

        /**
         * Reduces a possibly larger scalar value to {@code [0, l[} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param scalarHex the scalar to reduce in hexadecimal notation
         * @return the reduced scalar
         */
        default BigInteger cryptoCoreRistretto255ScalarReduce(String scalarHex) {
            if (scalarHex == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarReduce(toBin(scalarHex));
        }

        /**
         * Reduces a possibly larger scalar value to {@code [0, L[} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param scalar the scalar to reduce, must be
         *               {@link Ristretto255#RISTRETTO255_NON_REDUCED_SCALAR_BYTES}  bytes
         * @return the reduced scalar
         */
        BigInteger cryptoCoreRistretto255ScalarReduce(byte[] scalar);

        /**
         * Calculates the multiplicative inverse of the given scalar value.
         *
         * @param scalar the scalar to invert
         * @return the multiplicative inverse
         */
        default BigInteger cryptoCoreRistretto255ScalarInvert(BigInteger scalar)
            throws SodiumException {
            if (scalar == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarInvert(scalarToBytes(scalar));
        }

        /**
         * Calculates the multiplicative inverse of the given scalar value.
         *
         * @param scalarHex the scalar to invert in hexadecimal notation
         * @return the multiplicative inverse
         */
        default BigInteger cryptoCoreRistretto255ScalarInvert(String scalarHex)
            throws SodiumException {
            if (scalarHex == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarInvert(toBin(scalarHex));
        }

        /**
         * Calculates the multiplicative inverse of the given scalar value.
         *
         * @param scalar the scalar to invert, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @return the multiplicative inverse
         */
        BigInteger cryptoCoreRistretto255ScalarInvert(byte[] scalar) throws SodiumException;

        /**
         * Calculates the additive inverse of the given scalar value.
         *
         * @param scalar the scalar to negate
         * @return the additive inverse
         */
        default BigInteger cryptoCoreRistretto255ScalarNegate(BigInteger scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarNegate(scalarToBytes(scalar));
        }

        /**
         * Calculates the additive inverse of the given scalar value.
         *
         * @param scalarHex the scalar to negate in hexadecimal notation
         * @return the additive inverse
         */
        default BigInteger cryptoCoreRistretto255ScalarNegate(String scalarHex) {
            if (scalarHex == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarNegate(toBin(scalarHex));
        }

        /**
         * Calculates the additive inverse of the given scalar value.
         *
         * @param scalar the scalar to negate, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @return the additive inverse
         */
        BigInteger cryptoCoreRistretto255ScalarNegate(byte[] scalar);

        /**
         * Calculates the result R for the given scalar value such that {@code R + scalar = 1 (mod
         * L)} with {@code L} being the order of the Ristretto255 group.
         *
         * @param scalar the scalar to complement
         * @return the complement
         */
        default BigInteger cryptoCoreRistretto255ScalarComplement(BigInteger scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarComplement(scalarToBytes(scalar));
        }

        /**
         * Calculates the result R for the given scalar value such that {@code R + scalar = 1 (mod
         * L)} with {@code L} being the order of the Ristretto255 group.
         *
         * @param scalarHex the scalar to complement in hexadecimal notation
         * @return the complement
         */
        default BigInteger cryptoCoreRistretto255ScalarComplement(String scalarHex) {
            if (scalarHex == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarComplement(toBin(scalarHex));
        }

        /**
         * Calculates the result R for the given scalar value such that {@code R + scalar = 1 (mod
         * L)} with {@code L} being the order of the Ristretto255 group.
         *
         * @param scalar the scalar to complement, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @return the complement
         */
        BigInteger cryptoCoreRistretto255ScalarComplement(byte[] scalar);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar
         * @return the sum
         */
        default BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, BigInteger y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarAdd(scalarToBytes(x), scalarToBytes(y));
        }

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar in hexadecimal notation
         * @return the sum
         */
        default BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, String y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarAdd(scalarToBytes(x), toBin(y));
        }

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar
         * @return the sum
         */
        default BigInteger cryptoCoreRistretto255ScalarAdd(String x, BigInteger y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarAdd(toBin(x), scalarToBytes(y));
        }

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar in hexadecimal notation
         * @return the sum
         */
        default BigInteger cryptoCoreRistretto255ScalarAdd(String x, String y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarAdd(toBin(x), toBin(y));
        }

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the sum
         */
        default BigInteger cryptoCoreRistretto255ScalarAdd(String x, byte[] y) {
            if (x == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarAdd(toBin(x), y);
        }

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar in hexadecimal notation
         * @return the sum
         */
        default BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, String y) {
            if (y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarAdd(x, toBin(y));
        }

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the sum
         */
        default BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, byte[] y) {
            if (x == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarAdd(scalarToBytes(x), y);
        }

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar
         * @return the sum
         */
        default BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, BigInteger y) {
            if (y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarAdd(x, Ristretto255.scalarToBytes(y));
        }

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, byte[] y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar
         * @return the difference
         */
        default BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, BigInteger y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarSub(Ristretto255.scalarToBytes(x),
                Ristretto255.scalarToBytes(y));
        }

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar in hexadecimal notation
         * @return the difference
         */
        default BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, String y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarSub(Ristretto255.scalarToBytes(x), toBin(y));
        }

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar
         * @return the difference
         */
        default BigInteger cryptoCoreRistretto255ScalarSub(String x, BigInteger y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarSub(toBin(x), Ristretto255.scalarToBytes(y));
        }

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar in hexadecimal notation
         * @return the difference
         */
        default BigInteger cryptoCoreRistretto255ScalarSub(String x, String y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarSub(toBin(x), toBin(y));
        }

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the difference
         */
        default BigInteger cryptoCoreRistretto255ScalarSub(String x, byte[] y) {
            if (x == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarSub(toBin(x), y);
        }

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar in hexadecimal notation
         * @return the difference
         */
        default BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, String y) {
            if (y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarSub(x, toBin(y));
        }

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the difference
         */
        default BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, byte[] y) {
            if (x == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarSub(scalarToBytes(x), y);
        }

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar
         * @return the difference
         */
        default BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, BigInteger y) {
            if (y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarSub(x, scalarToBytes(y));
        }

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, byte[] y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar
         * @return the product
         */
        default BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, BigInteger y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarMul(scalarToBytes(x), scalarToBytes(y));
        }

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar in hexadecimal notation
         * @return the product
         */
        default BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, String y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarMul(scalarToBytes(x), toBin(y));
        }

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar
         * @return the product
         */
        default BigInteger cryptoCoreRistretto255ScalarMul(String x, BigInteger y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarMul(toBin(x), scalarToBytes(y));
        }

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar in hexadecimal notation
         * @return the product
         */
        default BigInteger cryptoCoreRistretto255ScalarMul(String x, String y) {
            if (x == null || y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarMul(toBin(x), toBin(y));
        }

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar in hexadecimal notation
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the product
         */
        default BigInteger cryptoCoreRistretto255ScalarMul(String x, byte[] y) {
            if (x == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarMul(toBin(x), y);
        }

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar in hexadecimal notation
         * @return the product
         */
        default BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, String y) {
            if (y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarMul(x, toBin(y));
        }

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the product
         */
        default BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, byte[] y) {
            if (x == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarMul(scalarToBytes(x), y);
        }

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar
         * @return the product
         */
        default BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, BigInteger y) {
            if (y == null) {
                throw new IllegalArgumentException("null arguments are invalid");
            }

            return cryptoCoreRistretto255ScalarMul(x, scalarToBytes(y));
        }

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, byte[] y);
    }

    class Checker {

        public static void ensurePointFits(byte[] point) {
            if (point == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as target arrays");
            }

            if (point.length < RISTRETTO255_BYTES) {
                throw new IllegalArgumentException(
                    "To hold a Ristretto255 point, the array must be "
                        + RISTRETTO255_BYTES
                        + " bytes in size");
            }
        }

        public static void ensureScalarFits(byte[] scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as target arrays");
            }

            if (scalar.length < RISTRETTO255_SCALAR_BYTES) {
                throw new IllegalArgumentException(
                    "To hold a Ristretto255 scalar, the array must be "
                        + RISTRETTO255_SCALAR_BYTES
                        + " bytes in size");
            }
        }

        public static void checkPoint(byte[] point) {
            if (point == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as Ristretto255 points");
            }

            if (point.length != RISTRETTO255_BYTES) {
                throw new IllegalArgumentException("A Ristretto255 point must be "
                                                       + RISTRETTO255_BYTES
                                                       + " bytes in size");
            }
        }

        public static void checkHash(byte[] hash) {
            if (hash == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as Ristretto255 hashes");
            }

            if (hash.length != RISTRETTO255_HASH_BYTES) {
                throw new IllegalArgumentException("A hash for use with Ristretto255 must be "
                                                       + RISTRETTO255_HASH_BYTES
                                                       + " bytes in size");
            }
        }

        public static void checkScalar(byte[] scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as Ristretto255 scalars");
            }

            if (scalar.length != RISTRETTO255_SCALAR_BYTES) {
                throw new IllegalArgumentException("A Ristretto255 scalar must be "
                                                       + RISTRETTO255_SCALAR_BYTES
                                                       + " bytes in size");
            }
        }

        public static void checkNonReducedScalar(byte[] scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as non-reduced Ristretto255 scalars");
            }

            if (scalar.length != RISTRETTO255_NON_REDUCED_SCALAR_BYTES) {
                throw new IllegalArgumentException("A non-reduced Ristretto255 scalar must be "
                                                       + RISTRETTO255_NON_REDUCED_SCALAR_BYTES
                                                       + " bytes in size");
            }
        }
    }

    final class RistrettoPoint {

        private final LazySodium ls;
        private final byte[] repr;

        private RistrettoPoint(LazySodium ls, byte[] repr) {
            if (repr == null || !ls.cryptoCoreRistretto255IsValidPoint(repr)) {
                throw new IllegalArgumentException("The passed point is invalid");
            }

            this.repr = repr;
            this.ls = ls;
        }

        private RistrettoPoint(LazySodium ls, String hex) {
            this(ls, toBin(hex));
        }

        @Override
        public String toString() {
            return toHex();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }

            if (!(o instanceof RistrettoPoint)) {
                return false;
            }

            RistrettoPoint that = (RistrettoPoint) o;
            return Arrays.equals(this.repr, that.repr);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(repr);
        }

        /**
         * Returns the hexadecimal notation of this point's canonical encoding.
         *
         * @return the point in hexadecimal notation
         */
        public String toHex() {
            return LazySodium.toHex(repr).toLowerCase();
        }

        /**
         * Returns this point's canonical encoding.
         *
         * @return the point
         */
        public byte[] toBytes() {
            return repr;
        }

        /**
         * Multiplies this point by a given scalar.
         *
         * @param n the scalar to multiply by
         * @return the multiplied point
         * @throws SodiumException if the result is zero
         */
        public RistrettoPoint scalarMult(BigInteger n) throws SodiumException {
            return ls.cryptoScalarmultRistretto255(n, this);
        }

        /**
         * Multiplies this point by a given scalar.
         *
         * @param n the scalar to multiply by
         * @return the multiplied point
         * @throws SodiumException if the result is zero
         */
        public RistrettoPoint times(BigInteger n) throws SodiumException {
            return scalarMult(n);
        }

        /**
         * Adds the given point to this point. Addition is commutative.
         *
         * @param other the point to add
         * @return the sum of both points
         * @throws SodiumException when the operation failed
         */
        public RistrettoPoint plus(RistrettoPoint other) throws SodiumException {
            return ls.cryptoCoreRistretto255Add(this, other);
        }

        /**
         * Subtracts the given point from this point.
         *
         * @param other the point to subtract
         * @return the difference of both points.
         * @throws SodiumException when the operation failed
         */
        public RistrettoPoint minus(RistrettoPoint other) throws SodiumException {
            return ls.cryptoCoreRistretto255Sub(this, other);
        }

        /**
         * Returns the additive inverse of this point. This is equivalent to {@code 0 - p} where 0
         * denotes the additive identity.
         *
         * @return the additive inverse
         * @throws SodiumException when the operation failed.
         */
        public RistrettoPoint negate() throws SodiumException {
            return zero(ls).minus(this);
        }

        /**
         * Returns the zero element (identity element) of the Ristretto255 group.
         *
         * @param ls the {@link LazySodium} instance
         * @return the identity element of Ristretto255
         */
        public static RistrettoPoint zero(LazySodium ls) {
            return fromBytes(ls, pointBuffer());
        }

        /**
         * Returns a random element of the Ristretto255 group.
         *
         * @param ls the {@link LazySodium} instance
         * @return a random element of Ristretto255
         */
        public static RistrettoPoint random(LazySodium ls) {
            return ls.cryptoCoreRistretto255Random();
        }

        /**
         * Returns the base point of the Ristretto255 group.
         *
         * @param ls the {@link LazySodium} instance
         * @return the base point of Ristretto255
         */
        public static RistrettoPoint base(LazySodium ls) throws SodiumException {
            return ls.cryptoScalarmultRistretto255Base(BigInteger.ONE);
        }

        /**
         * Creates a new {@link RistrettoPoint} from the hexadecimal representation. The hexadecimal
         * representation must be a valid canonical encoding.
         *
         * @param ls  the {@link LazySodium} instance
         * @param hex the Ristretto255 canonical encoding in hexadecimal notation
         * @return the corresponding {@link RistrettoPoint}
         */
        public static RistrettoPoint fromHex(LazySodium ls, String hex) {
            return new RistrettoPoint(ls, hex);
        }

        /**
         * Creates a new {@link RistrettoPoint} from the binary representation. The binary
         * representation must be a valid canonical encoding.
         *
         * @param ls    the {@link LazySodium} instance
         * @param bytes the Ristretto255 canonical encoding
         * @return the corresponding {@link RistrettoPoint}
         */
        public static RistrettoPoint fromBytes(LazySodium ls, byte[] bytes) {
            return new RistrettoPoint(ls, bytes);
        }
    }
}
