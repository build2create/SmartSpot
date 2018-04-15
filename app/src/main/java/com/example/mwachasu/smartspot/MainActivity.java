package com.example.mwachasu.smartspot;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiConfiguration.KeyMgmt;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.CountDownTimer;
import android.os.Handler;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.w3c.dom.Text;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Locale;
import java.util.TimeZone;
import java.util.zip.CRC32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static com.example.mwachasu.smartspot.TOTP.generateTOTP;


class TOTP {

    private TOTP() {
    }


    /**
     * This method is written as compatible with C version of the code
     */

    static String hmac_sha256(String key, String msg) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        char ipad[] = new char[64];
        char opad[] = new char[64];
        //ipad is 0x36 till 64 bytes
        //opad is 0x5c till 64 bytess
        for (int i = 0; i < 64; i += 2) {
            ipad[i] = '3';
            ipad[i + 1] = '6';
            opad[i] = '5';
            opad[i + 1] = 'c';
        }

        // H(y || H(x)) where
        // y=(k' XOR opad)
        // x=(K' XOR ipad)|| msg

        // <----------Right part------------>

        char rs[] = new char[64];
        for (int i = 0; i < key.length(); i++) {
            rs[i] = (char) (key.charAt(i) ^ ipad[i]); //(K' XOR ipad)
        }

        String y = new String(rs).concat(msg); //((K' XOR ipad)||m) = x
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] thedigest = md.digest(y.getBytes("UTF-8"));//H(x) = thedigest
        BigInteger bi = new BigInteger(1, thedigest);
        String right_side = bi.toString(16); //H(((K' XOR ipad)||m)) //right side in hexadecimal

        // <----------------Left part--------------->
        char ls[] = new char[64];
        for (int i = 0; i < key.length(); i++) {
            ls[i] = (char) (key.charAt(i) ^ opad[i]); //(K' XOR opad)=y
        }

        BigInteger bn1 = new BigInteger(1, new String(ls).getBytes());
        String x = bn1.toString(16).concat(right_side);//removed bn1 optimized here i.e. y in hex concatenated in right part
        x = "0" + x;

        byte ans1[] = md.digest(x.getBytes("UTF-8")); // H(y || H(x))
        bi = new BigInteger(1, ans1);
        String ans = bi.toString(16);
        return ans;
    }


    /**
     * This method converts a HEX string to Byte[]
     *
     * @param hex: the HEX string
     * @return: a byte array
     */

    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    private static final int[] DIGITS_POWER
            // 0 1 2 3 4 5 6 7 8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};


    public static String generateTOTP(String key, String time, String returnDigits) {
        // time is steps(multiple of 30 seconds)

        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;

        byte[] hash = new byte[0];
        try {
            hash = hmac_sha256(key, time).getBytes();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }
}

class OldClientThread implements Runnable {
    @Override
    public void run() {
        String uname = "Password";
        MessageDigest md = null;

        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] thedigest = new byte[0];

        try {
            thedigest = md.digest(uname.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            uname = Base64.getEncoder().encodeToString(thedigest);
        }
        //String j=uname.substring(0,uname.length()-4);
        String ans = new BigInteger(1, thedigest).toString(16);
        CRC32 crc32 = new CRC32();
        try {
            crc32.update(ans.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        String seed = (int) (-1L ^ crc32.getValue()) + "";
        seed = seed + seed + seed + seed + seed + seed + seed.substring(0, 4);
        // Seed for HMAC-SHA256 - 32 bytes
        long T0 = 0;
        Long X = MainActivity.maxtime / 1000;
        Log.d("X is", "**" + X.toString());
        final String DEFAULT = "N/A";
        String steps = "0";
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));


        SharedPreferences.Editor otp_editor = MainActivity.last_otp.edit();
        MainActivity.system_time = System.currentTimeMillis();
        MainActivity.time_last_generated = Long.parseLong(MainActivity.last_otp.getString("last_otp", DEFAULT));

        if ((MainActivity.system_time - MainActivity.time_last_generated) / 1000 > X) {
            //update the file last_otp_time
            otp_editor.putString("last_otp", MainActivity.system_time.toString());
            otp_editor.commit();
            //set the input time
            MainActivity.input_time = MainActivity.system_time / 1000;

        } else {
            MainActivity.input_time = (MainActivity.time_last_generated - 0) / 1000;

        }
                   /*T0=server_time%30;
                     if(T0>=15) {
	 		        	T0=-(30-T0);
	 		        }*/
        T0 = 0;
        long T = (MainActivity.input_time - T0) / X;

        String otp = generateTOTP(seed, T + "", "8");
        //  System.out.println("My otp:" + otp);

        final String string_otp = otp;
        Log.d("OTP:", otp);
        MainActivity.mOtpTextview.post(new Runnable() {
            @Override
            public void run() {
                //  MainActivity.mOtpTextview.setVisibility(View.VISIBLE);
                MainActivity.mOtpTextview.setText(string_otp);
                MainActivity.mOtpTextview.setVisibility(View.VISIBLE);

            }
        });
    }
}

class SetHotSpot implements Runnable {

    @Override
    public void run() {


    }
}

public class MainActivity extends AppCompatActivity {
    public static Long system_time, time_last_generated, input_time;
    static SharedPreferences last_otp, first_time;
    static TextView mOtpTextview,mWaitTextView;
    static Long maxtime;
    CountDownTimer mCountDownTimer;
    TextView mTimer;
    static Long mTimeLeftInMillis;
    EditText mTimeInput;
    Button mGenerate;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        last_otp = getSharedPreferences("last_otp", Context.MODE_PRIVATE);
        first_time = getSharedPreferences("first_time", Context.MODE_PRIVATE);
        mOtpTextview = (TextView) findViewById(R.id.otp);
        mWaitTextView =(TextView) findViewById(R.id.waitmesage);
        mGenerate = (Button) findViewById(R.id.generate);
        mTimer = (TextView) findViewById(R.id.timer);
        mTimeInput = (EditText) findViewById(R.id.maxtime);
        //logic to generate the TOTP

        mOtpTextview.setVisibility(View.INVISIBLE);
        if (!first_time.getBoolean("first_time", false)) {
            time_last_generated = System.currentTimeMillis();
            last_otp.edit().putString("last_otp", time_last_generated.toString()).commit();
            Toast.makeText(this, "First time done", Toast.LENGTH_LONG).show();
            first_time.edit().putBoolean("first_time", true).commit();
        }

        //set the tag for the button
        mGenerate.setTag(0);
        mGenerate.setText("Set Time");
        mWaitTextView.setVisibility(View.INVISIBLE);
        mGenerate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                final int status = (int) view.getTag();
                if (status == 0) {
                    if (mTimeInput.getText().toString().matches("")) {
                        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);

                        builder.setCancelable(true);
                        builder.setTitle("SMARTSPOT ALERT");
                        builder.setMessage("TIME cannot be blank");

                        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialogInterface, int i) {
                                dialogInterface.dismiss();
                            }
                        });
                        builder.show();
                        return;
                    }
                    //act like the set timer button
                    mTimeLeftInMillis = Long.parseLong(mTimeInput.getText().toString());
                    mTimeLeftInMillis = mTimeLeftInMillis * 1000 * 60;
                    maxtime = mTimeLeftInMillis;
                    updateCountdown();
                    mTimer.setVisibility(View.VISIBLE);
                    mTimeInput.setVisibility(View.INVISIBLE);
                    //change the text of set time to generate
                    mGenerate.setText("Generate OTP");
                    mGenerate.setTag(1);

                    // mSetTime.setVisibility(View.INVISIBLE);
                    //code copy pasted above
                } else if(status==1){
                    /*Handler h = new Handler();
                    h.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(MainActivity.this, maxtime.toString(), Toast.LENGTH_LONG).show();
                        }
                    }, 1000);
                    */

                    new Thread(new OldClientThread()).start();
                    mGenerate.setTag(2);
                    //Change the text to hotspot password
                    mGenerate.setText("Set as Hotspot Password");
                }
                else{
                    //functionality of the mSetHotSpot Password
                    //if on then switch off
                    if(MainActivity.isApOn(MainActivity.this)){
                        //turn it off
                        MainActivity.configApState(MainActivity.this);
                        //configure the wifi

                    }
                    WifiManager wifimanager = (WifiManager) getApplicationContext().getSystemService(getApplicationContext().WIFI_SERVICE);
                    /*if (wifimanager.isWifiEnabled()) {
                        wifimanager.setWifiEnabled(false);
                    }*/
                    mOtpTextview.setVisibility(View.VISIBLE);
                    WifiConfiguration config = new WifiConfiguration();
                    config.SSID = "Wifi";
                    config.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED);
                    config.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                    config.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
                    config.allowedKeyManagement.set(KeyMgmt.WPA_PSK);
                    config.preSharedKey = MainActivity.mOtpTextview.getText().toString();
                    mGenerate.setVisibility(View.INVISIBLE);
                    try {

                        Method method = wifimanager.getClass().getMethod("setWifiApEnabled", WifiConfiguration.class, boolean.class);
                        Object o=method.invoke(wifimanager, config, true);

                    } catch (Exception e) {

                    }

                    startTimer();

                }
            }
        });
        mTimer.setVisibility(View.INVISIBLE);
    }

    public static boolean isApOn(Context context) {
        WifiManager wifimanager = (WifiManager) context.getSystemService(context.WIFI_SERVICE);
        try {
            Method method = wifimanager.getClass().getDeclaredMethod("isWifiApEnabled");
            method.setAccessible(true);
            return (Boolean) method.invoke(wifimanager);
        }
        catch (Throwable ignored) {}
        return false;
    }


    public static boolean configApState(Context context) {
        WifiManager wifimanager = (WifiManager) context.getSystemService(context.WIFI_SERVICE);
        WifiConfiguration wificonfiguration = null;
        try {
            // if WiFi is on, turn it off
            if(isApOn(context)) {
                wifimanager.setWifiEnabled(false);
            }
            Method method = wifimanager.getClass().getMethod("setWifiApEnabled", WifiConfiguration.class, boolean.class);
            method.invoke(wifimanager, wificonfiguration, !isApOn(context));
            return true;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }



    private void startTimer() {

        mCountDownTimer = new CountDownTimer(mTimeLeftInMillis, 1000) {
            @Override
            public void onTick(long l) {
                mTimeLeftInMillis = l;
                updateCountdown();
            }

            @Override
            public void onFinish() {
                mGenerate.setText("Set Time");
                mGenerate.setTag(0);
                mGenerate.setVisibility(View.VISIBLE);
                mTimer.setVisibility(View.INVISIBLE);
                mTimeInput.setVisibility(View.VISIBLE);
                mOtpTextview.setVisibility(View.INVISIBLE);
            }
        }.start();


    }

    private void updateCountdown() {

        int minutes = (int) (mTimeLeftInMillis / 1000) / 60;
        int seconds = (int) (mTimeLeftInMillis / 1000) % 60;

        String leftFormatted = String.format(Locale.getDefault(), "%02d:%02d", minutes, seconds);
        mTimer.setText(leftFormatted);

    }
}
