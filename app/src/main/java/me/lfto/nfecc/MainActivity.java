package me.lfto.nfecc;

import android.content.Context;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;

import org.spongycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private NfcAdapter nfcAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton newKey = (FloatingActionButton) findViewById(R.id.generate);
        newKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Cryptowiz.newKeyPair();
                byte[] pubKey = Cryptowiz.publicKey().getEncoded();
                byte[] priKey = Cryptowiz.privateKey().getEncoded();
                Snackbar.make(view,
                        "New keypair generated!", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
                try {
                    log("----- KEY INFO -----");
                    log("Private key:\n" + new String(Base64.encode(priKey), "ASCII") + "\n");
                    log("Public key:\n" +  new String(Base64.encode(pubKey), "ASCII"));
                    log("----- KEY INFO -----");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        });

        Switch modeswitch = (Switch) findViewById(R.id.modeSwitch);
        modeswitch.setChecked(true);
        modeswitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

            @Override
            public void onCheckedChanged(CompoundButton buttonView,
                                         boolean isChecked) {

                if (isChecked) {
                    // Change to server mode
                    readerMode(true);
                    Log.i("Nfecc", "Switched to Server Mode");
                    log("Switched to Server Mode");
                } else {
                    // Change to HCE mode
                    Context context = getApplicationContext();
                    PackageManager pm = context.getPackageManager();
                    if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)) {
                        Log.e("Nfecc", "HCE is not supported!");
                        log("HCE is not supported!");
                        buttonView.setChecked(true);
                    } else {
                        readerMode(false);
                        Log.i("Nfecc", "Switched to HCE Mode");
                        log("Switched to HCE Mode");
                    }
                }

            }
        });

        TextView t=(TextView)findViewById(R.id.log);
        t.setMovementMethod(new ScrollingMovementMethod());

        // NFC
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter == null) {
            Log.e("Nfecc", "No NFC support!");
            log("No NFC support!");
            finish();
            return;
        }
        if (!nfcAdapter.isEnabled()) {
            Log.e("Nfecc", "NFC is disabled!");
            log("NFC is disabled!");
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        readerMode(true);
    }

    @Override
    public void onPause() {
        super.onPause();
        readerMode(false);
    }

    public void readerMode(boolean p) {
        if (p) {
            nfcAdapter.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                    null);
        } else {
            nfcAdapter.disableReaderMode(this);
        }
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        log("NEW TAG!");
        IsoDep isodep = IsoDep.get(tag);
        try {
            if (DepStuff.depInit(isodep)) {
                log("VALID TAG!");
            } else {
                log("BAD TAG!");
            }
        } catch (IOException e) {
            log("Failed to read TAG!");
            Log.e("Dep", e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    public synchronized void clearLog(View view) {
        TextView t=(TextView)findViewById(R.id.log);
        t.setText("");
        t.scrollTo(0,0);
    }

    public synchronized void log(String msg) {
        TextView t=(TextView)findViewById(R.id.log);
        t.append(msg + "\n");
    }
}
