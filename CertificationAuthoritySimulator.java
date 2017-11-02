package CA;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by djordjebozic on 5/25/16.
 */
public class CertificationAuthoritySimulator {
    private static KeyPair CAkeyPair;
    private static String IssuerName = "CN=Simulirano Sertifikaciono Telo,OU=Elektrotehnicki Fakultet,O=Univerzitet u Beogradu," +
            "L=Beograd,ST=Beograd,C=Srbija";
    private static String altIssuerName1 = "CN=Sertifikaciono telo,OU=ETF,O=Beogradski Univerzitet,"+
            "L=Beograd,ST=Centralna Srbija,C=Srbija";
    private static String altIssuerName2 = "CN=CA,OU=Univerzitet u Beogradu,O=Univerzitetska mreza,"+
            "L=Beograd,ST=Beograd,C=Srbija";

    private static BigInteger serialNumber = new BigInteger("1");
    private BigInteger serial = new BigInteger("1");


    private BasicConstraints basicConstraints;
    private KeyUsage keyUsage;
    private IssuerSerial issuerAlternativeNames;
    private Date notAfter;


    private boolean criticalityBC;
    private boolean criticalityKU;
    private boolean criticalityIA;


    public CertificationAuthoritySimulator() {
        KeyPairGenerator kg = null;

        try {
            kg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        kg.initialize(2048, new SecureRandom());
        CAkeyPair = kg.generateKeyPair();
        notAfter = null;

        basicConstraints = null;
        keyUsage = null;
        issuerAlternativeNames = null;
    }

    //moze proizvoljno da se menja
    public void setNotAfter(Date date) {
        notAfter = date;

    }

    public void resetNotAfter() {
        notAfter = null;
    }

    // moze proizvoljno da se menja
    public void setBasicConstraints(int i) {
            basicConstraints = new BasicConstraints(i);

    }

    public void resetBasicConstraints(){
        basicConstraints = null;
    }


    //moze proizvoljno da se menja
    public void setKeyUsage(boolean ds, boolean nr, boolean ke, boolean de, boolean ka, boolean kcs,
                            boolean crs, boolean eo, boolean doo) {

        int varArray[] = new int[9];
        for (int i = 0; i < 9; i++) {
            varArray[i] = 0;
        }


        if (ds == true) varArray[0] = KeyUsage.digitalSignature;
        if (nr == true) varArray[1] = KeyUsage.nonRepudiation;
        if (ke == true) varArray[2] = KeyUsage.keyEncipherment;
        if (de == true) varArray[3] = KeyUsage.dataEncipherment;
        if (ka == true) varArray[4] = KeyUsage.keyAgreement;
        if (kcs == true) varArray[5] = KeyUsage.keyCertSign;
        if (crs == true) varArray[6] = KeyUsage.cRLSign;
        if (eo == true) varArray[7] = KeyUsage.encipherOnly;
        if (doo == true) varArray[8] = KeyUsage.decipherOnly;
        int result = 1;
        for (int i = 0; i < 9; i++) {
            if(varArray[i]!=0) {
                result = result|varArray[i];
            }
        }
        keyUsage = new KeyUsage(result);
    }

    public void resetKeyUsage() {
        keyUsage = null;
    }

    //moze da se menja nakon postavljanja
    public void setIssuerAlternativeNames() throws IOException {
        if(issuerAlternativeNames==null) {
            GeneralNamesBuilder gnBuilder = new GeneralNamesBuilder();
            GeneralName alt1 = new GeneralName(new X500Name(altIssuerName1));
            GeneralName alt2 = new GeneralName(new X500Name(altIssuerName2));
            GeneralNames altNames = null;
            gnBuilder.addName(alt1);
            gnBuilder.addName(alt2);
            altNames = gnBuilder.build();
            issuerAlternativeNames = new IssuerSerial(altNames,new BigInteger("1"));
        }
    }

    public void resetIssuerAlternativeNames() {
        issuerAlternativeNames = null;
    }


    public void setCriticality(boolean bc, boolean ku, boolean ia) throws Exception{
        if ((bc&&basicConstraints == null) ^ (ku&&keyUsage==null) ^ (ia&&issuerAlternativeNames==null)) throw new Exception();
        criticalityIA = ia;
        criticalityBC = bc;
        criticalityKU = ku;
    }

    public void resetCriticality() {
        criticalityIA = false;
        criticalityBC = false;
        criticalityKU = false;
    }



    public X509Certificate sign(PKCS10CertificationRequest input) throws IOException, OperatorCreationException, CertificateException, NoSuchProviderException {
        AlgorithmIdentifier signing = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digesting = new DefaultDigestAlgorithmIdentifierFinder().find(signing);
        AsymmetricKeyParameter CApriv = PrivateKeyFactory.createKey(CAkeyPair.getPrivate().getEncoded());
        // ovo proveri da li radi
        SubjectPublicKeyInfo subKeyInfo = SubjectPublicKeyInfo.getInstance(input.getSubjectPublicKeyInfo().getEncoded());
        PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(input.getEncoded());

        serialNumber.add(new BigInteger("1"));
        serial = serialNumber;

        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(new X500Name(IssuerName),serial,
                new Date(), notAfter, pk10Holder.getSubject(),subKeyInfo);

        if (keyUsage != null) {
            myCertificateGenerator.addExtension(Extension.keyUsage, criticalityKU,keyUsage.toASN1Primitive());
        }
        if(basicConstraints != null) {
            myCertificateGenerator.addExtension(Extension.basicConstraints,criticalityBC,basicConstraints.toASN1Primitive());

        }
        if(issuerAlternativeNames!=null) {
            myCertificateGenerator.addExtension(Extension.issuerAlternativeName, criticalityIA, issuerAlternativeNames.getIssuer().toASN1Primitive());
        }



        ContentSigner signGen = new BcRSAContentSignerBuilder(signing,digesting).build(CApriv);
        X509CertificateHolder holder = myCertificateGenerator.build(signGen);
        Certificate x509CertStruct = holder.toASN1Structure();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream inputStream = new ByteArrayInputStream(x509CertStruct.getEncoded());
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(inputStream);
        inputStream.close();
        return certificate;
    }


    // kontrolne metode:

    public static KeyPair getKeyPair(){
        return CAkeyPair;
    }
    public BasicConstraints getBasicConstraints() {
        return basicConstraints;
    }
    public KeyUsage getKeyUsage() {
        return keyUsage;
    }

}