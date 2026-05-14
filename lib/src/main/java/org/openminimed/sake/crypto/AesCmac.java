package org.openminimed.sake.crypto;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;
import java.util.Objects;

/**
 * Stateful AES-CMAC over a 16-byte AES-128 key with a configurable truncation length.
 *
 * <p>The handshake uses both {@code macLen=8} (handshake CMAC chain) and
 * {@code macLen=4} (permit auth, SeqCrypt trailer prefix). BouncyCastle always
 * produces a 16-byte tag; we truncate to {@code macLen} bytes to match the
 * PyCryptodome {@code mac_len} parameter.</p>
 */
public final class AesCmac {

    /** AES block size and full MAC length in bytes. */
    public static final int BLOCK_SIZE = 16;

    private final CMac mac;
    private final int macLen;

    public AesCmac(byte[] key, int macLen) {
        Objects.requireNonNull(key, "key");
        if (key.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("AES-128 key must be " + BLOCK_SIZE + " bytes");
        }
        if (macLen < 1 || macLen > BLOCK_SIZE) {
            throw new IllegalArgumentException("macLen must be 1.." + BLOCK_SIZE);
        }
        this.mac = new CMac(AESEngine.newInstance());
        this.mac.init(new KeyParameter(key));
        this.macLen = macLen;
    }

    public AesCmac update(byte[] data) {
        Objects.requireNonNull(data, "data");
        mac.update(data, 0, data.length);
        return this;
    }

    public byte[] digest() {
        byte[] full = new byte[mac.getMacSize()];
        mac.doFinal(full, 0);
        if (macLen == full.length) {
            return full;
        }
        return Arrays.copyOf(full, macLen);
    }

    /**
     * Constant-time comparison against an expected tag.
     *
     * @return true if the computed digest matches {@code expected}, byte-for-byte.
     */
    public boolean verify(byte[] expected) {
        Objects.requireNonNull(expected, "expected");
        byte[] actual = digest();
        if (actual.length != expected.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < actual.length; i++) {
            diff |= actual[i] ^ expected[i];
        }
        return diff == 0;
    }
}
