package X509;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Locale;

/**
 * Created by djordjebozic on 5/25/16.
 */
public class CertificateControlBlock {

    private Locale dateLocale;
    private X500Name subject;
    private SubjectPublicKeyInfo publicKeyInfo;

    private X509Certificate signedCerificate;
    private X509Certificate selfSignedCertificate;



    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;

    private String alias; // ime za kljuceve

    private void setDateLocale() {
        if (dateLocale == null) {
            dateLocale = new Locale("en", "US");
        }
    }

    private void setPublicKeyInfo(PublicKey kPub) {
        if(publicKeyInfo == null) {
            publicKey = kPub;
            publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.29")), kPub.getEncoded());
        }
    }

    private void setSubject(String CN, String OU, String O, String L, String ST, String C, String E) {
        if (subject == null) {
            subject = new X500Name("CN="+CN+","+"OU="+OU+","+"O="+O+","+"L="+L+","+"ST="+ST+","+"C="+C+","+"E="+E);
        }
    }

    private void selfSign() throws OperatorCreationException, IOException, CertificateException {
        if (selfSignedCertificate == null && signedCerificate == null) {
            PKCS10CertificationRequest input = generateCSR();
            AlgorithmIdentifier signing = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
            AlgorithmIdentifier digesting = new DefaultDigestAlgorithmIdentifierFinder().find(signing);
            AsymmetricKeyParameter privateK = PrivateKeyFactory.createKey(privateKey.getEncoded());
            SubjectPublicKeyInfo subKeyInfo = SubjectPublicKeyInfo.getInstance(input.getSubjectPublicKeyInfo().getEncoded());
            PKCS10CertificationRequest pkcs10holder = new PKCS10CertificationRequest(input.getEncoded());

            X509v3CertificateBuilder myBuilder = new X509v3CertificateBuilder(subject, new BigInteger("0"),new Date(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis()+30*12*24*60*60*1000),pkcs10holder.getSubject(),subKeyInfo);


            ContentSigner signGen = new BcRSAContentSignerBuilder(signing,digesting).build(privateK);
            X509CertificateHolder myHolder = myBuilder.build(signGen);
            Certificate x509CertStruct = myHolder.toASN1Structure();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream inputStream = new ByteArrayInputStream(x509CertStruct.getEncoded());
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(inputStream);
            inputStream.close();
            selfSignedCertificate = certificate;
        }
    }

    private X509Certificate getSignedCertificate() {
        return signedCerificate;
    }
    private X509Certificate getSelfSignedCertificate() {
        return selfSignedCertificate;
    }


    public CertificateControlBlock(int keySize, String alias, String CN, String OU,
                                   String O, String L, String ST, String C, String E) {
        dateLocale = null;
        subject = null;
        publicKeyInfo = null;

        signedCerificate = null;
        selfSignedCertificate = null;
        this.alias = alias;

        setDateLocale();
        setSubject(CN,OU,O,L,ST,C,E);

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize, new SecureRandom());
            KeyPair kp = keyPairGenerator.generateKeyPair();
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();
            setPublicKeyInfo(publicKey);
        } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
        }
        try {
            selfSign();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
                e.printStackTrace();
        }


    }

    public CertificateControlBlock(X509Certificate certificate, PrivateKey privateKey,String alias) {
        this.alias = alias;
        publicKey = certificate.getPublicKey();
        this.privateKey = privateKey;
        X500Principal principal = certificate.getIssuerX500Principal();
        subject = new X500Name(principal.getName());
        setDateLocale();
        setPublicKeyInfo(certificate.getPublicKey());
        if(certificate.getSerialNumber().equals(new BigInteger("0"))) {
            this.selfSignedCertificate = certificate;
        } else {
            this.signedCerificate = certificate;
        }
    }

    public PKCS10CertificationRequest generateCSR() throws OperatorCreationException {
        if (signedCerificate == null) {
            ContentSigner signGen = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
            PKCS10CertificationRequest csr = builder.build(signGen);
            return csr;
        }
        else return null;
    }

    public void setSignedCertificate(X509Certificate certificate) {
        if (signedCerificate == null) {
            if (!publicKey.equals(certificate.getPublicKey())) return;
            if (!subject.equals(new X500Name(certificate.getSubjectX500Principal().getName()))) return;
            signedCerificate = certificate;
        }
    }



    public String getAlias() {
        return alias;
    }

    public X509Certificate getCertificate() {
        if (signedCerificate != null) {
            return getSignedCertificate();
        }
        else return getSelfSignedCertificate();
    }


    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public String getCertificateInfo() {
        if (signedCerificate!= null) {
            StringBuilder builder = new StringBuilder();
            builder.append("SERTIFIKAT JESTE POTPISAN!").append("\n");
            builder.append(alias).append("\n").append(signedCerificate.toString());
            return builder.toString();
        }
        else {
            StringBuilder builder = new StringBuilder();
            builder.append("SERTIFIKAT NIJE POTPISAN!").append("\n");
            //builder.append(alias).append("\n").append(subject.toString()).append("\n");
            //builder.append(publicKey.toString());
            builder.append(selfSignedCertificate.toString());
            return builder.toString();
        }
    }

    public boolean isSigned() {
        if (signedCerificate!=null) return true;
        else return false;
    }


}
