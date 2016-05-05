package me.lfto.nfecc;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import org.spongycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;

public class MainActivity extends AppCompatActivity {

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
                    TextView t=(TextView)findViewById(R.id.log);
                    t.append("----- KEY INFO -----" + "\n\n");
                    t.append("Private key:\n" + new String(Base64.encode(priKey), "ASCII") + "\n\n");
                    t.append("Public key:\n" +  new String(Base64.encode(pubKey), "ASCII") + "\n\n");
                    t.append("----- KEY INFO -----" + "\n");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        });
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

    public void clearLog(View view) {
        TextView t=(TextView)findViewById(R.id.log);
        t.setText("");
    }
}
