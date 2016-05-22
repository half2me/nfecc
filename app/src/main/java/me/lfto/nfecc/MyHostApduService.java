package me.lfto.nfecc;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

public class MyHostApduService extends HostApduService {

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        if (selectAidApdu(apdu)) {
            Log.i("APDU", "AID");
            return Cryptowiz.publicKey().getEncoded();
        } else if (requestSignMessage(apdu)) {
            Log.i("APDU", "SIGN");
            return Cryptowiz.sign(apdu);
        }
        Log.i("APDU", "MSG: " + new String(apdu));
        return "Unknown message!".getBytes();
    }

    @Override
    public void onDeactivated(int reason) {
        Log.i("Nfecc", "Deactivated: " + reason);
    }

    private boolean selectAidApdu(byte[] apdu) {
        return apdu.length >= 2 && apdu[0] == (byte)0 && apdu[1] == (byte)0xa4;
    }

    private boolean requestSignMessage(byte[] apdu) {
        return apdu[0] == 'S' && apdu[1] == 'I' && apdu[2] == 'G' && apdu[3] == 'N';
    }
}
