package me.lfto.nfecc;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECParameterSpec;

/**
 * ECDA details:
 * Key encapsulation: PKCS8
 * Elliptic curve: NIST P-256
 */
public class Cryptowiz {

    private static KeyPairGenerator g;

    private static KeyPair kp;

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

        try {
            g = KeyPairGenerator.getInstance("ECDSA", "SC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public static void newKeyPair() {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        try {
            g.initialize(ecSpec, new SecureRandom());
            kp = g.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
