package me.lfto.nfecc;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * ECDA details:
 * Key encapsulation: PKCS8
 * Elliptic curve: NIST P-256
 */
public class Cryptowiz {

    private static KeyStore ks;

    static {
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (!ks.containsAlias("nfecc")) {
                newKeyPair("nfecc");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate a new keypair
     */
    public static void newKeyPair(String alias) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA512)
                    .build());
            KeyPair kp = kpg.generateKeyPair();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Get a certificate in X509
     *
     * @return cert
     */
    public static Certificate getCertificate(String alias) throws Exception {
        ks.load(null);
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            Log.w("CryptoWizz", "No certificate called " + alias);
            throw new Exception("No such certificate!");
        }
        return cert;
    }

    public static void addCertificate(String alias, Certificate certificate) {
        try {
            ks.load(null);
            ks.setCertificateEntry(alias, certificate);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void addCertificate(String alias, byte[] certificate) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(certificate);
            X509Certificate cert = (X509Certificate)cf.generateCertificate(in);
            addCertificate(alias, cert);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }

    public static boolean aliasExists(String alias) {
        try {
            ks.load(null);
            return ks.containsAlias(alias);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
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
            ks.load(null);
            PrivateKey key = (PrivateKey) ks.getKey("nfecc", null);
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(key);
            s.update(data);
            return s.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Verify digital signature
     *
     * @param data data that was signed
     * @param alias alias of the cert
     * @param signature signature
     * @return result of validation
     */
    public static boolean verify(byte[] data, String alias, byte[] signature) {
        try {
            ks.load(null);
            Certificate cert = ks.getCertificate(alias);
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(cert);
            s.update(data);
            return s.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
