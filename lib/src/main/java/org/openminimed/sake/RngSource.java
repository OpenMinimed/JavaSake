package org.openminimed.sake;

/**
 * Source of random bytes used to populate handshake fields the server / client
 * are expected to choose freshly per session.
 *
 * <p>The default implementation is backed by {@link java.security.SecureRandom}.
 * Tests can substitute a deterministic source to drive a server or client
 * against a captured packet trace.</p>
 */
public interface RngSource {

    /** @return {@code n} fresh random bytes. */
    byte[] nextBytes(int n);
}
