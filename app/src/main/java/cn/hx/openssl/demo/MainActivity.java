package cn.hx.openssl.demo;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import cn.hx.openssl.android.AESUtil;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        try {
            byte[] encryptedArray = AESUtil.encrypt_AES_CBC_128("hello".getBytes(), "0123456789123456".getBytes(), "0123456789123456".getBytes());
            String decryptedString = new String(AESUtil.decrypt_AES_CBC_128(encryptedArray, "0123456789123456".getBytes(), "0123456789123456".getBytes()));
            tv.setText(decryptedString);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
