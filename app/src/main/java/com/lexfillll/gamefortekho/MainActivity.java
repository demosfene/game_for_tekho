package com.lexfillll.gamefortekho;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.constraintlayout.widget.Group;
import androidx.core.content.ContextCompat;

import com.facebook.stetho.Stetho;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Random;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainActivity extends AppCompatActivity {

    private static final String HIDDEN_NUMBER = "hiddenNumber";
    private static final String APP_PREFERENCE = "appSettings";
    private static final String HIDDEN_NUMBER_IV = "hiddenNumberIV";
    private ImageButton bPlay;
    private EditText etNumber;
    private Button bGuess;
    private Integer enterNumber;
    private TextView tvErrorMassage;
    private Group gameGroup;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;
    private String KEY_NAME;
    private Integer hiddenNumber;
    private boolean readyToEncrypt = false;
    private SharedPreferences sharedPreferences;
    private Button bRegenerate;
    private String sPHiddenNumber;
    private byte[] encryptedHiddenNumber;
    private byte[] encryptionIV;
    private TextView tvHint;
    private TextView tvCongratulation;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Stetho.initializeWithDefaults(this);

        KEY_NAME = getString(R.string.secret_key_name);
        biometricPrompt = createBiometricPrompt();
        bPlay = findViewById(R.id.button_play);
        bRegenerate = findViewById(R.id.button_regenerate);
        bGuess = findViewById(R.id.button_guess);
        tvHint = findViewById(R.id.tv_hint);
        tvErrorMassage = findViewById(R.id.tv_error_massage);
        tvCongratulation = findViewById(R.id.tv_congratulation);
        etNumber = findViewById(R.id.et_enter_the_number);
        gameGroup = findViewById(R.id.group);
        bRegenerate.setOnClickListener(v -> {
                    etNumber.getText().clear();
                    loadHiddenNumber();
                }
        );
        bPlay.setVisibility(View.VISIBLE);
        sharedPreferences = getSharedPreferences(APP_PREFERENCE, Context.MODE_PRIVATE);
        bPlay.setOnClickListener(v -> {
            sharedPreferences.edit().remove(HIDDEN_NUMBER).apply();
            loadHiddenNumber();
        });

        bGuess.setOnClickListener(v -> {
            try {
                tvErrorMassage.setVisibility(View.GONE);
                enterNumber = Integer.parseInt(etNumber.getText().toString());
                switch (enterNumber.compareTo(hiddenNumber)) {
                    case 1:
                        tvHint.setVisibility(View.VISIBLE);
                        tvHint.setText(R.string.hint_less);
                        break;
                    case 0:
                        finishGame();
                        break;
                    case -1:
                        tvHint.setVisibility(View.VISIBLE);
                        tvHint.setText(R.string.hint_larger);
                        break;
                }
            } catch (NumberFormatException e) {
                tvErrorMassage.setVisibility(View.VISIBLE);
                tvErrorMassage.setText(R.string.error_not_number);
            }
        });
    }

    private void loadHiddenNumber() {
        biometricPrompt = createBiometricPrompt();
        promptInfo = createPromptInfo();
        if (sharedPreferences.contains(HIDDEN_NUMBER)) {
            readyToEncrypt = false;
            sPHiddenNumber = sharedPreferences.getString(HIDDEN_NUMBER, "");
            String sPEncryptionIV = sharedPreferences.getString(HIDDEN_NUMBER_IV, "");
            encryptedHiddenNumber = Base64.decode(sPHiddenNumber, Base64.DEFAULT);
            encryptionIV = Base64.decode(sPEncryptionIV, Base64.DEFAULT);
        } else {
            readyToEncrypt = true;
        }
        Cipher cipher = generateCipher();
        biometricPrompt.authenticate(promptInfo,
                new BiometricPrompt.CryptoObject(cipher));
    }

    private BiometricPrompt.PromptInfo createPromptInfo() {
        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric login for my app")
                .setNegativeButtonText("Use account password")
                .build();
        return promptInfo;
    }

    //Create user biometric authentication
    private BiometricPrompt createBiometricPrompt() {
        Executor executor = ContextCompat.getMainExecutor(this);
        biometricPrompt = new BiometricPrompt(MainActivity.this,
                executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(getApplicationContext(),
                        "Authentication error: " + errString, Toast.LENGTH_SHORT)
                        .show();
            }

            @Override
            public void onAuthenticationSucceeded(
                    @NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                startGame();
                if (readyToEncrypt) {
                    encryptHiddenNumber(result);
                } else {
                    decryptHiddenNumber(result);
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(getApplicationContext(), "Authentication failed",
                        Toast.LENGTH_SHORT)
                        .show();
            }
        });
        return biometricPrompt;
    }

    private void startGame() {
        bPlay.setVisibility(View.GONE);
        tvCongratulation.setVisibility(View.GONE);
        gameGroup.setVisibility(View.VISIBLE);
    }

    private void finishGame() {
        sharedPreferences.edit().remove(HIDDEN_NUMBER).apply();
        gameGroup.setVisibility(View.GONE);
        tvHint.setVisibility(View.GONE);
        bRegenerate.setVisibility(View.VISIBLE);
        tvCongratulation.setVisibility(View.VISIBLE);

    }

    private void decryptHiddenNumber(BiometricPrompt.AuthenticationResult result) {
        try {
            String stringDecryptHiddenNumber = new String(result.getCryptoObject().getCipher().doFinal(encryptedHiddenNumber), StandardCharsets.UTF_8);
            hiddenNumber = Integer.parseInt(stringDecryptHiddenNumber);
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace();
        }
    }

    private void encryptHiddenNumber(BiometricPrompt.AuthenticationResult result) {
        try {
            hiddenNumber = new Random().nextInt(10000);
            byte[] cipherText = result.getCryptoObject().getCipher().doFinal(String.valueOf(hiddenNumber).getBytes(StandardCharsets.UTF_8));
            String saveThis = Base64.encodeToString(cipherText, Base64.DEFAULT);
            sharedPreferences.edit().putString(HIDDEN_NUMBER, saveThis).apply();
            sharedPreferences.edit().putString(HIDDEN_NUMBER_IV, Base64.encodeToString(result.getCryptoObject().getCipher().getIV(), Base64.DEFAULT)).apply();
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    //generate Secret key in AndroidKeyStore
    private void generateSecretKey(KeyGenParameterSpec keyGenParameterSpec) throws InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, getString(R.string.androidProvider));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        assert keyGenerator != null;
        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();
    }

    //loads a secret key from AndroidKeyStore or generates a key if it was not generated
    private SecretKey getSecretKey() throws CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore keyStore = KeyStore.getInstance(getString(R.string.androidProvider));
        // Before the keystore can be accessed, it must be loaded.
        keyStore.load(null);
        if (!keyStore.containsAlias(KEY_NAME)) {
            generateSecretKey(
                    new KeyGenParameterSpec.Builder(
                            KEY_NAME,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .setUserAuthenticationRequired(true)
                            .setInvalidatedByBiometricEnrollment(false)
                            .build());
        }
        return ((SecretKey) keyStore.getKey(KEY_NAME, null));
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }

    //generate Cipher for encrypt/decrypt hidden number
    private Cipher generateCipher() {
        Cipher cipher = null;
        try {
            cipher = getCipher();
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecretKey secretKey = null;
        try {
            secretKey = getSecretKey();
        } catch (CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableKeyException | KeyStoreException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        assert cipher != null;
        if (readyToEncrypt) {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        } else {
            try {
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(encryptionIV));
            } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
        }
        return cipher;
    }
}