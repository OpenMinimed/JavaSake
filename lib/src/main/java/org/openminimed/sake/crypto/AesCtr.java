package org.openminimed.sake.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * AES-128 CTR stream encryption.
 *
 * <p>The 16-byte IV is treated as the initial 128-bit counter and incremented
 * by one per block. Callers are responsible for assembling the IV such that
 * the counter region does not wrap into the nonce region.</p>
 *
 * <p>CTR is symmetric so the same method is used to encrypt and decrypt.</p>
 */
public final class AesCtr {

    /** AES block size and IV length in bytes. */
    public static final int BLOCK_SIZE = 16;

    private AesCtr() {
    }

    public static byte[] crypt(byte[] key, byte[] iv, byte[] data) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(iv, "iv");
        Objects.requireNonNull(data, "data");
        if (key.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("AES-128 key must be " + BLOCK_SIZE + " bytes");
        }
        if (iv.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("IV must be " + BLOCK_SIZE + " bytes");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES/CTR/NoPadding unavailable", e);
        }
    }
}
