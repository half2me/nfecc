package me.lfto.nfecc;

import android.nfc.tech.IsoDep;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class DepStuff {
    private static final byte[] CLA_INS_P1_P2 = { 0x00, (byte)0xA4, 0x04, 0x00 };
    private static final byte[] AID_ANDROID = { (byte)0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };

    private static byte[] createSelectAidApdu(byte[] aid) {
        byte[] result = new byte[6 + aid.length];
        System.arraycopy(CLA_INS_P1_P2, 0, result, 0, CLA_INS_P1_P2.length);
        result[4] = (byte)aid.length;
        System.arraycopy(aid, 0, result, 5, aid.length);
        result[result.length - 1] = 0;
        return result;
    }

    public static boolean depInit(IsoDep isoDep) throws IOException {
        Boolean success = false;
        Log.i("Dep", "Attempting to connect...");
        isoDep.connect();
        Log.i("Dep", "Connected! Sending AID APDU...");
        byte[] response = isoDep.transceive(createSelectAidApdu(AID_ANDROID));
        try {
            PublicKey friendKey = Cryptowiz.decodePublicKey(response);
            if (Cryptowiz.knownKeys.contains(friendKey)) {
                Log.i("Dep", "Known key received! Validating...");
            } else {
                Cryptowiz.knownKeys.add(friendKey);
                Log.i("Dep", "Stored new key! Validating...");
            }

            // Validation
            SecureRandom random = new SecureRandom();
            byte[] payload = ("SIGN" + new BigInteger(130, random).toString(32)).getBytes();
            response = isoDep.transceive(payload);
            if (Cryptowiz.verify(payload, friendKey, response)) {
                Log.i("Dep", "Verification successull!");
                success = true;
            } else {
                Log.e("Dep", "Verification failed!");
            }

        } catch (InvalidKeySpecException e) {
            Log.e("Dep", e.getMessage());
        }
        isoDep.close();
        Log.i("Dep", "Close");

        return success;
    }


}
