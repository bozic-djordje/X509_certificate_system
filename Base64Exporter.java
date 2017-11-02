package base64;

import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by djordjebozic on 5/27/16.
 */
public class Base64Exporter {
    private Base64Exporter() {}
    public static Base64Exporter instance = null;
    public static Base64Exporter getInstance() {
        if (instance == null) instance = new Base64Exporter();
        return instance;
    }
    public String getCertBase64Encoded(X509Certificate cert) {
        try {
            String sTmp = new String(Base64.encode(cert.getEncoded()));
            String sEncoded = "-----BEGIN_CERT-----" + "\r\n";
            for (int iCnt = 0; iCnt < sTmp.length(); iCnt += 64) {
                int iLineLength;
                if (iCnt + 64 > sTmp.length()) {
                    iLineLength = sTmp.length() - iCnt;
                } else {
                    iLineLength = 64;
                }
                sEncoded = sEncoded + sTmp.substring(iCnt, iCnt + iLineLength) + "\r\n";
            }
            sEncoded = sEncoded + "-----END_CERT-----" + "\n";
            return sEncoded;
        } catch (CertificateException e) {
        e.printStackTrace();
        }
        return null;
    }

    public void saveX509toFile(String filePath, X509Certificate cert) {
        String newFilePath = filePath;
        if(!filePath.endsWith(".cer")) {
            newFilePath = filePath + ".cer";
        }
        if (!(new File(newFilePath)).exists()) {
            FileWriter output;
            try {
                output = new FileWriter(newFilePath, false);
                output.write(getCertBase64Encoded(cert));
                output.flush();
                output.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}
