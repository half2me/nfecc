package me.lfto.nfecc;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

public class MyHostApduService extends HostApduService {

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        Log.i("Nfecc", "IN: " + new String(apdu));
        if (selectAidApdu(apdu)) {
            return "Hello World".getBytes();
        }
        return "Yo - lo".getBytes();
    }

    @Override
    public void onDeactivated(int reason) {
        Log.i("Nfecc", "Deactivated: " + reason);
    }

    private boolean selectAidApdu(byte[] apdu) {
        return apdu.length >= 2 && apdu[0] == (byte)0 && apdu[1] == (byte)0xa4;
    }
}
