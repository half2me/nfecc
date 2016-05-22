package me.lfto.nfecc;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.util.encoders.Base64;

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
import java.security.Signature;
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

    public void importKeyPair(String publicKey, String privateKey) {
        try {
            // Import public key
            X509EncodedKeySpec x509ks = new X509EncodedKeySpec(
                    Base64.decode(publicKey));
            PublicKey pub = kf.generatePublic(x509ks);

            // Import private key
            PKCS8EncodedKeySpec p8ks = new PKCS8EncodedKeySpec(
                    Base64.decode(privateKey));
            PrivateKey priv = kf.generatePrivate(p8ks);

            // Save to keypair
            kp = new KeyPair(pub, priv);

        } catch (InvalidKeySpecException e) {
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

    /**
     * Sign data with the private key
     *
     * @param data bytes to sign
     * @return signature
     */
    public static byte[] sign(byte[] data) {
        try {
            Signature s = Signature.getInstance("NONEwithECDSA", "SC");
            s.initSign(kp.getPrivate());
            s.update(data);
            return s.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Verify digital signature
     * @param data data that was signed
     * @param key public key
     * @param sig signature
     * @return result of validation
     */
    public static boolean verify(byte[] data, PublicKey key, byte[] sig){
        try {
            Signature signer = Signature.getInstance("NONEwithECDSA", "SC");
            signer.initVerify(key);
            signer.update(data);
            return (signer.verify(sig));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
