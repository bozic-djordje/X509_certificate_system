package X509;

import java.util.ArrayList;

/**
 * Created by djordjebozic on 5/27/16.
 */
public class ControlBlockList {
    private ArrayList<CertificateControlBlock> certificates;

    public ControlBlockList() {
        certificates = new ArrayList<>();
    }

    public void addCertificate(CertificateControlBlock ccb) {
        for (int i = 0; i < certificates.size(); i++) {
            if(ccb.getAlias().equals(certificates.get(i).getAlias())) {
                return;
            }
        }
        certificates.add(ccb);
    }

    public void removeCertificate(String alias) {
        for (int i = 0; i < certificates.size(); i++) {
            if(alias.equals(certificates.get(i).getAlias())) {
                certificates.remove(i);
                break;
            }
        }
    }

    public CertificateControlBlock getCertificateControlBlock(String alias) {
        for (int i = 0; i < certificates.size(); i++) {
            if (alias.equals(certificates.get(i).getAlias())) {
                return certificates.get(i);
            }
        }
        return null;
    }
    public String getAllCertificateAliases() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < certificates.size(); i++) {
            builder.append(certificates.get(i).getAlias());
            builder.append("\n");
        }
        return builder.toString();
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<POCETAK ISPISA>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>").append("\n").append("\n");
        int i = 0;
        for (i = 0; i < certificates.size(); i++) {
            builder.append(certificates.get(i).getCertificateInfo());
            builder.append("\n");
            builder.append("\n");
        }
        builder.append("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<KRAJ ISPISA>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        return builder.toString();
    }
}
