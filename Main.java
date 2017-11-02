
package TackeProjekta;

import CA.CertificationAuthoritySimulator;
import Keystore.*;
import X509.CertificateControlBlock;
import X509.ControlBlockList;
import base64.Base64Exporter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.function.BooleanSupplier;


/**
 * Created by djordjebozic on 6/13/16.
 */

public class Main {
    public static void main(String[] args) {
        ControlBlockList certificates = new ControlBlockList();
        CertificationAuthoritySimulator CA = new CertificationAuthoritySimulator();
        boolean works = true;

        while(works) {
            System.out.println("\n\nOdaberite sta zelite da uradite:\n");
            System.out.println("1. Kreiranje novog para kljuceva\n");
            System.out.println("2. Izvoz para kljuceva u fajl\n");
            System.out.println("3. Potpisivanje para kljuceva\n");
            System.out.println("4. Izvoz sertifikata u base64\n");
            System.out.println("5. Kreiranje novog fajla za cuvanje kljuceva: .p12\n");
            System.out.println("6. Pregled postojecih kljuceva\n");
            System.out.println("7. Zavrsetak rada\n\n");
            int opt = Integer.parseInt(readLineInput());

            try {
                switch (opt) {
                    case 1:
                        createNewKeyPair(certificates);
                        break;
                    case 2:
                        exportKeyPair(certificates);
                        break;
                    case 3:
                        signKeyPair(certificates, CA);
                        break;
                    case 4:
                        exportCertificate(certificates);
                        break;
                    case 5:
                        createFile();
                        break;
                    case 6:
                        listKeys(certificates);
                        break;
                    case 7:
                        works = false;
                        break;
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (NoSuchAlias noSuchAlias) {
                noSuchAlias.printStackTrace();
            }
        }
        System.out.println("");

    }

    private static String readLineInput() {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String input = null;
        try {
            input = bufferedReader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return input;
    }


    private static void createNewKeyPair(ControlBlockList certificates) throws FileNotFoundException,
    NoSuchAlias {
        System.out.println("Da li zelite da kreirate novi par kljuceva\n" +
                "ili da importujete kljuc u lokalnu bazu iz fajla?\n");
        System.out.println("1. Novi par kljuceva\n");
        System.out.println("2. Importovati iz faja\n");
        int option = Integer.parseInt(readLineInput());
        CertificateControlBlock newKeypair = null;


        if (option == 1) {
            //parametri za novi par kljuceva
            System.out.println("Unesite velicinu kljuca:\n");
            int keySize = Integer.parseInt(readLineInput());

            System.out.println("Unesite alias za par kljuceva:\n");
            String alias = readLineInput();

            System.out.println("Unesite CommonName za korisnika:\n");
            String CN = readLineInput();

            System.out.println("Unesite OrganizationalUnit za korisnika:\n");
            String OU = readLineInput();

            System.out.println("Unesite Organization za korisnika:\n");
            String O = readLineInput();

            System.out.println("Unesite Locality za korisnika:\n");
            String L = readLineInput();

            System.out.println("Unesite State za korisnika:\n");
            String ST = readLineInput();

            System.out.println("Unesite Country za korisnika:\n");
            String C = readLineInput();

            System.out.println("Unesite email za korisnika:\n");
            String E = readLineInput();

            newKeypair = new CertificateControlBlock(keySize,alias,CN,OU,O,L,ST,C,E);
        }
        else if (option == 2){
            //uvoz sertifikata iz fajla
            //Napomena 1: Korisnik mora da navede kako je enkriptovao fajl da bi se znalo kako
            // se vrsi dekripcija
            //Napomena 2: Korisnik mora da navede da li je sertifikat koji se nalazi u fajlu legitiman
            // odnosno da li ga je CA potpisalo ili ne da bi se znalo kako se pravi CertificateControlBlock
            System.out.println("Unesite filePath (BEZ EKSTENZIJE)!\n");
            String filePath = readLineInput();
            System.out.println("Navedite alias kljuceva koji zelite da uvezete:\n");
            String alias = readLineInput();
            System.out.println("Unesite sifru kojom je fajl zasticen:\n");
            String password = readLineInput();
            System.out.println("Kako zelite da nazovete ovaj par kljuceva: \n");
            String newAlias = readLineInput();

            KeyStoreManager kmg = KeyStoreManager.getInstance();
            try {
                X509Certificate certFromFile = kmg.getCertificate(filePath,alias,password);
                PrivateKey privateKey = kmg.getPrivateKey(filePath,alias,password);
                newKeypair = new CertificateControlBlock(certFromFile,privateKey,newAlias);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        // cuvanje para kljuceva
        certificates.addCertificate(newKeypair);
    }

    private static void exportKeyPair(ControlBlockList certificates) throws FileNotFoundException,
    NoSuchAlias {
        // unos parametara
        System.out.println("Unesite alias para kljuceva koji zelite da izvezete:\n");
        String keyAlias = readLineInput();
        CertificateControlBlock keysForExport = certificates.getCertificateControlBlock(keyAlias);
        if(keysForExport == null) throw new NoSuchAlias();

        // pita korisnika da li zeli da produzi sa izvozenjem para kljuceva ako nije zvanican
        // tj. ako ga CA nije potpisao vec je samopotpisan
        // izlazi iz funkcije ako korisnik resi da ne zeli takav par kljuceva da izveze
        if (!keysForExport.isSigned()) {
            System.out.println("Par kljuceva nije zvanicno potpisan, da li zelite da nastavite?\n");
            System.out.println("1. da");
            System.out.println("2. ne");
            int exit = Integer.parseInt(readLineInput());
            if (exit == 2) return;
        }


        System.out.println("Unesite ime fajla u koji zelite da izvezete par kljuceva: \n");
        System.out.println("Napomena 1: Ako fajl ne postoji bice napravljen \n");
        String fileName = readLineInput();

        System.out.println("Unesite sifru kojom je fajl zasticen: ");
        System.out.println("Napomena 1: Sifra ne sme biti duza od 16 karaktera\n");
        System.out.println("Ukoliko pravite novi fajl ova sifra ce biti koriscena za zastitu istog \n");
        String password = readLineInput();
        System.out.println("Da li zelite da faj zastitite AES algoritmom: (true/false)\n");
        boolean aes = Boolean.parseBoolean(readLineInput());

        // pravljenje fajla sa zadatom siform ako vec nije postojao
        // i cuvanje para kljuceva
        //Napomena: KeyStoreManager proveri da li fajl postoji pre pravljenja
        KeyStoreManager kmg = KeyStoreManager.getInstance();
        try {
            kmg.createFile(fileName,password,aes);
            kmg.storeEntry(keysForExport,fileName,password);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }

    private static void signKeyPair(ControlBlockList certificates,CertificationAuthoritySimulator CA) throws NoSuchAlias {
        // odabir parametara za potpisivanje, ovo radi sertifikator
        //prvo moraju prethodni da se resetuju
        CA.resetBasicConstraints();
        CA.resetCriticality();
        CA.resetIssuerAlternativeNames();
        CA.resetKeyUsage();
        CA.resetNotAfter();

        //samo setovanje
        System.out.println("Unesite da li zelite BasicConstraints ekstenziju: (true/false)\n");
        boolean BC = Boolean.parseBoolean(readLineInput());
        boolean BCC = false;
        if (BC == true) {
            System.out.println("Da li zelite da ova ekstenzija bude kriticna: (true/false)\n");
            BCC = Boolean.parseBoolean(readLineInput());
            //unos parametara za BC ekstenziju
            System.out.println("Unesite duzinu certificateList puta:\n");
            int length = Integer.parseInt(readLineInput());
            CA.setBasicConstraints(length);
        }

        System.out.println("Unesite da li zelite KeyUsage ekstenziju: (true/false)\n");
        boolean KU = Boolean.parseBoolean(readLineInput());
        boolean KUC = false;
        if (KU == true) {
            System.out.println("Da li zelite da ova ekstenzija bude kriticna: (true/false)\n");
            KUC = Boolean.parseBoolean(readLineInput());
            //unos parametara za KU ekstenziju
            // PAZNJA: Sledece parametre treba isto da unosi korisnik, ali nema svrhe
            // da sada kucam unos za iste jer ih ima 8 :S
            CA.setKeyUsage(true,true,true,true,true,true,true,false,false);
        }

        System.out.println("Unesite da li zelite IssuerAlts ekstenziju: (true/false)\n");
        boolean IA = Boolean.parseBoolean(readLineInput());
        boolean IAC = false;
        if (IA == true) {
            System.out.println("Da li zelite da ova ekstenzija bude kriticna: (true/false)\n");
            IAC = Boolean.parseBoolean(readLineInput());
            try {
                CA.setIssuerAlternativeNames();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        //postavljanje kritikalnosti ekstenzija
        try {
            CA.setCriticality(BCC,KUC,IAC);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // postavljanje datuma
        System.out.println("Unesite datum u formatu: MM/dd//yyyy\n ");
        String endDateString = readLineInput();
        DateFormat df = new SimpleDateFormat("MM/dd/yyyy");
        Date endDate;
        try {
            endDate = df.parse(endDateString);
            CA.setNotAfter(endDate);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        // KRAJ SETOVANJA PARAMETARA ZA POTPISIVANJE

        // dohvatanje sertifikata koji potpisujemo
        System.out.println("Unesite alias kljuca koji zelite da potpisete: \n");
        String alias = readLineInput();
        CertificateControlBlock toBeSigned = certificates.getCertificateControlBlock(alias);
        if(toBeSigned == null) throw new NoSuchAlias();

        System.out.println("INFORMACIJE O SERTIFIKATU: \n\n");
        System.out.println(toBeSigned.getCertificateInfo());
        System.out.println("\n\n Da li zelite da nastavite? (true/false)");
        boolean option = Boolean.parseBoolean(readLineInput());
        if(!option) return;

        //generisanje CSR-a
        PKCS10CertificationRequest csr = null;
        try {
            csr = toBeSigned.generateCSR();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }

        //prosledjivanje csr-a CA-u i potpisivanje
        X509Certificate signedCertificate = null;
        try {
            signedCertificate = CA.sign(csr);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        // postavljanje zvanicnog, potpisanog sertifikata
        // sada CertificateControlBlock ima zvanicni, potpisani sertifikat

        toBeSigned.setSignedCertificate(signedCertificate);
    }

    private static void exportCertificate(ControlBlockList certificates) throws NoSuchAlias, FileNotFoundException {
        Base64Exporter base64 = Base64Exporter.getInstance();
        System.out.println("Da li zelite da eksportujete sertifikat iz fajla ili iz lokalne baze: \n");
        System.out.println("1. Lokalna baza\n");
        System.out.println("2. Fajl\n");
        int opt = Integer.parseInt(readLineInput());

        if(opt == 1) {
            System.out.println("Unesite alias kljuca: \n");
            String keyAlias = readLineInput();
            CertificateControlBlock ccb = certificates.getCertificateControlBlock(keyAlias);
            if (ccb == null) throw new NoSuchAlias();
            if (ccb.isSigned() == false) {
                System.out.println("Sertifikat je samopotpisan, nema validnog potpisa.\n" +
                        "Da li zelite da nastavite? (true/false)\n");
                boolean opt1 = Boolean.parseBoolean(readLineInput());
                if (opt1 == false) return;
            }
            X509Certificate certificatetoBeExported = ccb.getCertificate();

            System.out.println("Unesite ime fajla koji ce biti napravljen i u koji eksportujete sertifikat: \n");
            System.out.println("Napomena: ime fajla navedite sa .cer ekstenzijom \n");
            String fileName = readLineInput();
            base64.saveX509toFile(fileName,certificatetoBeExported);
        }
        else if(opt == 2) {
            System.out.println("Unesite ime fajla iz kog zelite da eksportujete sertifikat: \n");
            String fileName = readLineInput();
            System.out.println("Unesite alias kljuca: \n");
            String keyAlias = readLineInput();
            System.out.println("Unesite sifru kojom je fajl zasticen: \n");
            String password = readLineInput();
            System.out.println("Da li je fajl zasticen AES-om: (true/false)\n");
            boolean aes = Boolean.parseBoolean(readLineInput());

            X509Certificate certificateToBeExported = null;
            try {
                KeyStoreManager kmg = KeyStoreManager.getInstance();
                certificateToBeExported = kmg.getCertificate(fileName,keyAlias,password);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }

            System.out.println("Unesite ime fajla koji ce biti napravljen i u koji eksportujete sertifikat: \n");
            String fileName2 = readLineInput();
            base64.saveX509toFile(fileName2,certificateToBeExported);
        }
    }

    private static void createFile() {
        System.out.println("Unesite ime fajla u koji zelite da napravite: \n");
        String fileName = readLineInput();

        System.out.println("Unesite sifru kojom ce se zastititi fajl: \n ");
        System.out.println("Napomena 1: Sifra ne sme biti duza od 16 karaktera!\n");
        String password = readLineInput();
        System.out.println("Da li zelite da faj zastitite AES algoritmom: (true/false)\n");
        boolean aes = Boolean.parseBoolean(readLineInput());

        // pravljenje fajla
        KeyStoreManager kmg = KeyStoreManager.getInstance();
        try {
            kmg.createFile(fileName,password,aes);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private static void listKeys(ControlBlockList certificates) {
        System.out.println("Da li zelite da pregled kljuca iz fajla ili svih kljuceva iz lokalne baze? \n");
        System.out.println("1. Fajl\n");
        System.out.println("2. Lokalna baza\n");
        int option = Integer.parseInt(readLineInput());

        if (option == 1) {
            System.out.println("Navedite filePath: \n");
            String filePath = readLineInput();
            System.out.println("Navedite sifru kojom je fajl zasticen: \n");
            String password = readLineInput();
            System.out.println("Navedite da li ste fajl zastitili AES-om: (true/false)\n");
            boolean aes = Boolean.parseBoolean(readLineInput());
            System.out.println("Unesite alias sertifikata koji zelite da pogledate:\n");
            String alias = readLineInput();
            KeyStoreManager kmg = KeyStoreManager.getInstance();

            try {
                System.out.println(kmg.getCertificate(filePath,alias,password).toString());
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }


        }
        else if (option == 2) {
            System.out.println(certificates.toString());
        }

    }
}

