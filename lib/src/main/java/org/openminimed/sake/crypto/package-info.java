/**
 * Thin AES primitive wrappers used by the SAKE handshake.
 *
 * <p>AES-ECB and AES-CTR are served by the JDK's JCE provider. AES-CMAC is
 * implemented via BouncyCastle as the JDK does not ship it.</p>
 */
package org.openminimed.sake.crypto;
