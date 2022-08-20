/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.bo180447dpm180609d;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import javafx.util.Pair;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;

/**
 *
 * @author Miki
 */
public class KeyPairUtil {

    public static void export(PGPKeyRing key, String fileName) throws FileNotFoundException, IOException {
        try (ArmoredOutputStream out = new ArmoredOutputStream(new FileOutputStream(fileName))) {
            key.encode(out);
        }
    }

    public static PGPKeyRing importKeyRing(String fileName) throws FileNotFoundException, IOException, PGPException {
        PGPObjectFactory pgpF = new PGPObjectFactory(PGPUtil.getDecoderStream(new FileInputStream(fileName)),
                new BcKeyFingerprintCalculator());

        Object o = pgpF.nextObject();

        if (o instanceof PGPPublicKeyRing) {
            return (PGPKeyRing) o;
        }
        if (o instanceof PGPSecretKeyRing) {
            return (PGPKeyRing) o;
        }
        if (o instanceof PublicKeyPacket) {
            PublicKeyPacket p = (PublicKeyPacket) o;
            ArrayList<PGPPublicKey> temparr = new ArrayList<>();
            temparr.add(new PGPPublicKey(p, new BcKeyFingerprintCalculator()));
            PGPPublicKeyRing pgpPublicKeyRing = new PGPPublicKeyRing(temparr);
            return pgpPublicKeyRing;
        }
        if (o instanceof SecretKeyPacket) {
            SecretKeyPacket s = (SecretKeyPacket) o;
            ArrayList<PGPSecretKey> temparr = new ArrayList<>();
            temparr.add(
                    new PGPSecretKey(s, new PGPPublicKey(s.getPublicKeyPacket(), new BcKeyFingerprintCalculator())));
            PGPSecretKeyRing pgpSecretKeyRing = new PGPSecretKeyRing(temparr);
            return pgpSecretKeyRing;
        }
        return null;
    }

    public static PGPPrivateKey extractPrivateKey(PGPSecretKey MasterSecretKey, char[] password) throws PGPException {
        PBESecretKeyDecryptor decryptorFactory = new BcPBESecretKeyDecryptorBuilder(
                new BcPGPDigestCalculatorProvider()).build(password);
        return MasterSecretKey.extractPrivateKey(decryptorFactory);
    }

    public static boolean correctPassword(PGPSecretKey MasterSecretKey, char[] password) {
        try {
            extractPrivateKey(MasterSecretKey, password);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static Pair<PGPPublicKeyRing, PGPSecretKeyRing> generateKey(int keySize, String id, char[] passphrase)
            throws Exception {
        Pair<PGPKeyPair, PGPKeyPair> keyPairPair = PGPKeyPairsGenerator(keySize);

        PGPDigestCalculator checksumCalculator = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);

        BcPGPContentSignerBuilder keySignerBuilder = new BcPGPContentSignerBuilder(
                keyPairPair.getKey().getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);

        PBESecretKeyEncryptor keyEncryptor = new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5)
                .build(passphrase);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                keyPairPair.getKey(),
                id,
                checksumCalculator,
                null,
                null,
                keySignerBuilder,
                keyEncryptor);

        keyRingGen.addSubKey(keyPairPair.getValue());

        return new Pair<PGPPublicKeyRing, PGPSecretKeyRing>(
                keyRingGen.generatePublicKeyRing(),
                keyRingGen.generateSecretKeyRing());
    }

    private static Pair<PGPKeyPair, PGPKeyPair> PGPKeyPairsGenerator(int RSASize) throws PGPException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();

        keyPairGenerator.init(new RSAKeyGenerationParameters(RSAKeyGenParameterSpec.F4, new SecureRandom(), RSASize,
                PrimeCertaintyCalculator.getDefaultCertainty(RSASize)));

        return new Pair<>(
                new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, keyPairGenerator.generateKeyPair(), new Date()),
                new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, keyPairGenerator.generateKeyPair(), new Date()));
    }
}
