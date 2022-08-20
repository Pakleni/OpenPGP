/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package etf.openpgp.bo180447dpm180609d;

import etf.openpgp.bo180447dpm180609d.UI.PGProjectFrame;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureGenerator;

import javafx.util.Pair;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 *
 * @author hides
 */
public class Main {
    public static ArrayList<PGPPublicKeyRing> publicKeyList = new ArrayList<>();
    public static ArrayList<PGPSecretKeyRing> secretKeyList = new ArrayList<>();

    public static void newKey(int RSASize, String keyName, String email, char[] password) throws Exception {

        Pair<PGPPublicKeyRing, PGPSecretKeyRing> generateKey = KeyPairUtil.generateKey(RSASize,
                email.isEmpty() ? keyName : keyName + " <" + email + ">", password);

        publicKeyList.add(generateKey.getKey());
        secretKeyList.add(generateKey.getValue());
    }

    public static void saveKey(String fileName, int key, boolean isPublic) throws Exception {
        KeyPairUtil.export((isPublic ? publicKeyList : secretKeyList).get(key), fileName);
    }

    public static void importKey(String fileName) throws FileNotFoundException, IOException, PGPException {
        PGPKeyRing o = KeyPairUtil.importKeyRing(fileName);

        if (o instanceof PGPPublicKeyRing) {
            publicKeyList.add((PGPPublicKeyRing) o);
        }
        if (o instanceof PGPSecretKeyRing) {
            secretKeyList.add((PGPSecretKeyRing) o);
        }
    }

    public static void messageSend(boolean toEncrypt, boolean toSign, boolean toZIP, boolean toRadix64, int encryptKey,
            String encryptAlgo, int signKey, char[] password, String inputFile, String outputFile)
            throws IOException, PGPException {

        OutputStream encryptionStream = null, outputFileStream = null, compressionStream = null, current;
        PGPSignatureGenerator signatureGenerator = null;
        OPGPCript cryptor = new OPGPCript();
        current = outputFileStream = cryptor.getFile(outputFile, toRadix64);

        if (toEncrypt) {
            int encryptionAlgorithm = encryptAlgo.equals("3DES") ? PGPEncryptedData.TRIPLE_DES : PGPEncryptedData.CAST5;
            current = encryptionStream = cryptor.encrypt(current, publicKeyList.get(encryptKey), encryptionAlgorithm);
        }
        if (toZIP) {
            current = compressionStream = cryptor.compress(current);
        }
        if (toSign) {
            signatureGenerator = cryptor.sign(current, secretKeyList.get(signKey), password);
        }

        cryptor.flush(outputFileStream, current, inputFile, signatureGenerator, compressionStream, encryptionStream);
    }

    public static String[] getPublicKeyNames() {
        String[] publicKeyNames = new String[Main.publicKeyList.size()];

        for (int i = 0; i < Main.publicKeyList.size(); i++) {
            Iterator<PGPPublicKey> list = Main.publicKeyList.get(i).getPublicKeys();
            PGPPublicKey curr = null;
            while (list.hasNext()) {
                curr = list.next();
                if (curr.isMasterKey()) {
                    break;
                }
            }
            if (curr == null)
                publicKeyNames[i] = "unnamed";
            else
                publicKeyNames[i] = curr.getUserIDs().next();
        }

        return publicKeyNames;
    }

    public static String[] getPrivateKeyNames() {
        String[] secretKeyNames = new String[Main.secretKeyList.size()];

        for (int i = 0; i < Main.secretKeyList.size(); i++) {
            Iterator<PGPSecretKey> list = Main.secretKeyList.get(i).getSecretKeys();
            PGPSecretKey curr = null;
            while (list.hasNext()) {
                curr = list.next();
                if (curr.isMasterKey()) {
                    break;
                }
            }
            if (curr == null)
                secretKeyNames[i] = "unnamed";
            else
                secretKeyNames[i] = curr.getUserIDs().next();
        }

        return secretKeyNames;
    }

    public static void deletePublic(int i) {
        publicKeyList.remove(i);
    }

    public static boolean deletePrivate(int i, char[] password) {
        Iterator<PGPSecretKey> list = Main.secretKeyList.get(i).getSecretKeys();
        PGPSecretKey curr = null;
        while (list.hasNext()) {
            curr = list.next();
            if (curr.isMasterKey()) {
                break;
            }
        }

        if (curr == null)
            return false;

        if (KeyPairUtil.correctPassword(curr, password)) {
            secretKeyList.remove(i);
            return true;
        }

        return false;
    }

    public static String recieveFile(String inputFile, String outputFile, char[] password)
            throws SignatureException, IOException, PGPException {

        return OPGPCript.decrypt(inputFile, outputFile, password, new PGPSecretKeyRingCollection(secretKeyList),
                new PGPPublicKeyRingCollection(publicKeyList));
    }

    public static void main(String[] args)
            throws Exception {

        // char[] pass = "abc".toCharArray();
        //
        // newKey(1024, "generisani kljuc", "pace@giox.mandrake.net", pass);
        //
        // saveKey("testing/keyPublic.asc", 0, true);
        // saveKey("testing/keySecret.asc", 0, false);
        //
        // messageSend(true, true, true, true, 0, "3DES", 0, pass, "testing/en.txt",
        // "testing/en.pgp");

        PGProjectFrame.main(args);
    }
}
