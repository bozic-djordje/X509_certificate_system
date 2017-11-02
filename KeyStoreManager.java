package Keystore;

import X509.CertificateControlBlock;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Created by djordjebozic on 6/14/16.
 */
public class KeyStoreManager {
    private static byte[] salt;
    private static byte[] iv;
    private static KeyStoreManager instance = null;
    private static byte[] ID;
    private KeyStoreManager(){
        salt = new byte[]{0x0000,0x0001,0x0002,0x0003};
        iv = new byte[]{0x0000,0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,
                0x0008,0x0009,0x000A,0x000B,0x000C,0x000D,0x000E,0x000F};
        ID = new byte[]{0x0000,0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,
                0x0008,0x0009,0x000A,0x000B,0x000C,0x000D,0x000E,0x000F};

    }
    public static KeyStoreManager getInstance() {
        if(instance == null) instance = new KeyStoreManager();
        return instance;
    }

    private SecretKey generateAESKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKey sc = keyFactory.generateSecret(spec);
        SecretKey keyAES = new SecretKeySpec(sc.getEncoded(), "AES");
        return keyAES;
    }

    private byte[] decrypt(byte[] buffer, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE,(SecretKey)generateAESKey(password), ivspec);
        byte[] plaintext = cipher.doFinal(buffer);
        return plaintext;

    }

    private byte[] encrypt (byte[] buffer, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE,(SecretKey)generateAESKey(password), ivspec);
        byte[] ciphertext = cipher.doFinal(buffer);
        return ciphertext;

    }

    private byte[] createBuffer(FileInputStream fis, boolean option) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int buff;
        if (option) fis.skip(16);
        while((buff = fis.read())!=-1) {
            buffer.write(buff);
        }
        fis.close();
        return buffer.toByteArray();
    }

    private void storeBuffer(FileOutputStream fos, byte[] buffer, boolean option) throws IOException {
        fos.flush();
        if(option) fos.write(ID);
        fos.write(buffer);
        fos.close();
    }

    private void unlockFile(String filePath, String password) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filePath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        byte[] encryptedBuffer_l = new byte[0];
        try {
            encryptedBuffer_l = createBuffer(fis,true);
        } catch (IOException e) {
            e.printStackTrace();
        }
        //dekriptujem podatke
        byte[] decryptedBuffer_l = null;
        try {
            decryptedBuffer_l = decrypt(encryptedBuffer_l, password);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // brisem enkriptovane podatke i cuvam dekriptovane
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(filePath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            storeBuffer(fos,decryptedBuffer_l,false);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private void lockFile(String filePath, String password) {
        // citam dekriptovane podatke
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filePath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        byte[] decryptedBuffer_s = new byte[0];
        try {
            decryptedBuffer_s = createBuffer(fis,false);
        } catch (IOException e) {
            e.printStackTrace();
        }
        // enkriptujem podatke
        byte[] encryptedBuffer_s = null;
        try {
            encryptedBuffer_s = encrypt(decryptedBuffer_s,password);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        //brisem dekriptovane podatke i cuvam enkriptovane
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(filePath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            storeBuffer(fos,encryptedBuffer_s,true);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private boolean isAES(String filePath) {
        boolean aes = false;
        byte[] buffer = new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        try {
            FileInputStream fis = new FileInputStream(filePath);
            fis.read(buffer,0,16);
            if(Arrays.equals(ID,buffer)) aes = true;
            fis.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return aes;
    }

    // FUNKCIJA: KREIRANJE NOVOG FAJLA (putDoFajlaBezEkstenzije, sifra, AESiliNE)
    public void createFile(String filePath, String password, boolean option) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        // pravilno kreiranje imena fajla
        String newFilePath = filePath;
        if(!filePath.endsWith(".p12")) {
            newFilePath = filePath + ".p12";
        }

        //ako fajl vec postoji ne radi se nista
        File file = new File(newFilePath);
        if (file.exists()) {
            return;
        }

        // kreiranje novog fajla
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(null,password.toCharArray());

        java.io.FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(newFilePath);
            ks.store(fos,password.toCharArray());
        } finally {
            if (fos != null) {
                fos.close();
            }
        }

        // ako je odabrano da se fajl enkriptuje aes-om dodatno
        if (option) {
            lockFile(newFilePath,password);
        }
    }




    public void storeEntry(CertificateControlBlock certificate, String filePath, String password) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        String newFilePath = filePath;
        if(!filePath.endsWith(".p12")) {
            newFilePath = filePath + ".p12";
        }
        boolean aes = false;
        if(isAES(newFilePath)) {
            unlockFile(newFilePath,password);
            aes = true;
        }

        KeyStore ks = KeyStore.getInstance("pkcs12");
        FileInputStream fis = new FileInputStream(newFilePath);
        ks.load(fis,password.toCharArray());
        fis.close();

        Certificate chain[] = new Certificate[1];
        chain[0] = certificate.getCertificate();
        ks.setKeyEntry(certificate.getAlias(),(PrivateKey)certificate.getPrivateKey(),password.toCharArray(),chain);


        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream(newFilePath);
            ks.store(fos,password.toCharArray());
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
        if(aes) lockFile(newFilePath,password);
    }

    public PrivateKey getPrivateKey(String filePath, String alias, String password) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        String newFilePath = filePath;
        if(!filePath.endsWith(".p12")) {
            newFilePath = filePath + ".p12";
        }
        boolean aes = false;
        if(isAES(newFilePath)) {
            unlockFile(newFilePath,password);
            aes = true;
        }

        KeyStore ks = KeyStore.getInstance("pkcs12");
        FileInputStream fis = new FileInputStream(newFilePath);
        ks.load(fis,password.toCharArray());
        fis.close();


        PrivateKey kpriv = null;
        try {
            kpriv = (PrivateKey)ks.getKey(alias,password.toCharArray());
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream(newFilePath);
            ks.store(fos,password.toCharArray());
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
        if(aes) lockFile(newFilePath,password);
        return kpriv;
    }

    public X509Certificate getCertificate(String filePath, String alias, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        String newFilePath = filePath;
        if(!filePath.endsWith(".p12")) {
            newFilePath = filePath + ".p12";
        }
        boolean aes = false;
        if(isAES(newFilePath)) {
            unlockFile(newFilePath,password);
            aes = true;
        }

        KeyStore ks = KeyStore.getInstance("pkcs12");
        FileInputStream fis = new FileInputStream(newFilePath);
        ks.load(fis,password.toCharArray());
        fis.close();

        X509Certificate certificate = null;
        certificate = (X509Certificate) ks.getCertificate(alias);

        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream(newFilePath);
            ks.store(fos,password.toCharArray());
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
        if(aes) lockFile(newFilePath,password);
        return certificate;
    }
}
