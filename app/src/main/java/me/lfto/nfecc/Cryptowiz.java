package me.lfto.nfecc;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ECDA details:
 * Key encapsulation: PKCS8
 * Elliptic curve: NIST P-256
 */
public class Cryptowiz {

    private static KeyPairGenerator g;
    private static KeyFactory kf;
    private static KeyPair kp;

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

        try {
            g = KeyPairGenerator.getInstance("ECDSA", "SC");
            kf = KeyFactory.getInstance("ECDSA", "SC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate a new keypair
     */
    public static void newKeyPair() {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        try {
            g.initialize(ecSpec, new SecureRandom());
            kp = g.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the public key in X509
     *
     * @return public key
     */
    public static PublicKey publicKey() {
        if (kp == null) {
            newKeyPair();
        }
        try {
            return kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Get the private key in PKCS8
     *
     * @return private key
     */
    public static PrivateKey privateKey() {
        if (kp == null) {
            newKeyPair();
        }
        try {
            return kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }
}
