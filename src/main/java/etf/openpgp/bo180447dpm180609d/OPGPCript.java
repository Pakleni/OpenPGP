/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.bo180447dpm180609d;

import static etf.openpgp.bo180447dpm180609d.KeyPairUtil.extractPrivateKey;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

/**
 *
 * @author Miki
 */
public class OPGPCript {

    public OPGPCript() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public OutputStream getFile(String fileName, boolean radix64) throws FileNotFoundException {
        OutputStream out = new FileOutputStream(fileName);

        if (radix64) {
            out = new ArmoredOutputStream(out);
        }

        return out;
    }

    public OutputStream encrypt(OutputStream out, PGPPublicKeyRing publicKey, int encAlgorithm)
            throws IOException, PGPException {
        BcPGPDataEncryptorBuilder dataEncryptor;

        dataEncryptor = new BcPGPDataEncryptorBuilder(encAlgorithm)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom());

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);

        PGPPublicKey found = null;

        for (Iterator<PGPPublicKey> iterator = publicKey.getPublicKeys(); iterator.hasNext();) {
            PGPPublicKey obj = iterator.next();
            if (obj.isEncryptionKey()) {
                found = obj;
                break;
            }
        }

        if (found != null) {
            encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(found));
            return encryptedDataGenerator.open(out, new byte[1 << 16]);
        }

        return null;
    }

    public OutputStream compress(OutputStream out) throws IOException, PGPException {
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        return compressedDataGenerator.open(out, new byte[1 << 16]);
    }

    public PGPSignatureGenerator sign(OutputStream out, PGPSecretKeyRing secretKey, char[] password)
            throws PGPException, IOException {
        PGPSecretKey next;
        for (Iterator<PGPSecretKey> iterator = secretKey.getSecretKeys(); iterator.hasNext();) {
            next = iterator.next();
            if (next.isSigningKey())
                break;
        }

        PBESecretKeyDecryptor decryptorFactory = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                .build(password);

        PGPPrivateKey privateKey = secretKey.getSecretKey().extractPrivateKey(decryptorFactory);

        PGPContentSignerBuilder contentSignerBuilder = new BcPGPContentSignerBuilder(
                secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        signatureGenerator.generateOnePassVersion(false).encode(out);

        return signatureGenerator;
    }

    public void flush(OutputStream outputFileStream, OutputStream current, String inputFile,
            PGPSignatureGenerator signatureGenerator,
            OutputStream compressionStream, OutputStream encryptionStream)
            throws IOException, PGPException {
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOutputStream = literalDataGenerator.open(current, PGPLiteralData.BINARY, inputFile,
                new Date(), new byte[1 << 16]);

        FileInputStream inputFileStream = new FileInputStream(inputFile);
        byte[] buffer = new byte[1 << 16];

        for (int length = inputFileStream.read(buffer); length > 0; length = inputFileStream.read(buffer)) {
            literalOutputStream.write(buffer, 0, length);
            if (signatureGenerator != null)
                signatureGenerator.update(buffer, 0, length);
        }

        inputFileStream.close();
        literalDataGenerator.close();
        if (signatureGenerator != null)
            signatureGenerator.generate().encode(current);
        if (compressionStream != null)
            compressionStream.close();
        if (encryptionStream != null)
            encryptionStream.close();
        outputFileStream.close();
    }

    public static String decrypt(
            String inputFile,
            String outputFile,
            char[] password,
            PGPSecretKeyRingCollection secretKeyCollection,
            PGPPublicKeyRingCollection publicKeyCollection)
            throws IOException, PGPException, SignatureException {
        try (OutputStream outputStream = new FileOutputStream(outputFile)) {

            FileInputStream inputStream = new FileInputStream(inputFile);
            InputStream decoderStream = PGPUtil.getDecoderStream(inputStream);

            PGPObjectFactory current = new PGPObjectFactory(decoderStream, new BcKeyFingerprintCalculator());

            Object o = current.nextObject();

            // Decrypt data
            if (o instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) o;

                PGPEncryptedData encryptedData = null;

                boolean found = false;
                for (Iterator<PGPEncryptedData> i = encryptedDataList.getEncryptedDataObjects(); i.hasNext();) {
                    encryptedData = i.next();

                    PGPPublicKeyEncryptedData pgppked = ((PGPPublicKeyEncryptedData) encryptedData);

                    long keyID = pgppked.getKeyID();
                    PGPSecretKey sk = secretKeyCollection.getSecretKey(keyID);

                    if (KeyPairUtil.correctPassword(sk, password)) {
                        found = true;
                        InputStream encryptedDataStream = pgppked
                                .getDataStream(new BcPublicKeyDataDecryptorFactory(extractPrivateKey(sk, password)));
                        current = new PGPObjectFactory(encryptedDataStream, new BcKeyFingerprintCalculator());
                        break;
                    }
                }

                if (!found) {
                    throw new PGPException("Password error/No valid secret key");
                }
            }

            ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

            PGPOnePassSignatureList onePassSignatureList = null;
            PGPSignatureList signatureList = null;

            // Decompress/Extract signatures
            while ((o = current.nextObject()) != null) {
                if (o instanceof PGPCompressedData) {
                    current = new PGPObjectFactory(((PGPCompressedData) o).getDataStream(),
                            new BcKeyFingerprintCalculator());
                    o = current.nextObject();
                }

                if (o instanceof PGPLiteralData) {
                    PGPLiteralData literalData = (PGPLiteralData) o;

                    InputStream literalDataStream = literalData.getInputStream();
                    int c;

                    while ((c = literalDataStream.read()) >= 0) {
                        byteOutputStream.write(c);
                    }
                } else if (o instanceof PGPOnePassSignatureList) {
                    onePassSignatureList = (PGPOnePassSignatureList) o;
                } else if (o instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) o;
                }
            }

            byteOutputStream.close();
            byte[] byteArray = byteOutputStream.toByteArray();

            outputStream.write(byteArray);
            outputStream.flush();
            outputStream.close();

            String signed = "";

            // File not signed
            if (onePassSignatureList == null || signatureList == null) {
                return signed;
            }

            // Check signature
            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);
                PGPPublicKey publicKey = publicKeyCollection.getPublicKey(onePassSignature.getKeyID());

                if (publicKey != null) {
                    onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
                    onePassSignature.update(byteArray);
                    PGPSignature signature = signatureList.get(i);

                    if (onePassSignature.verify(signature)) {
                        for (Iterator<String> j = publicKey.getUserIDs(); j.hasNext();) {
                            signed += j.next() + '\n';
                        }
                    } else {
                        throw new SignatureException("Signature Check Failed");
                    }
                } else {
                    throw new PGPException("No valid public key");
                }

            }
            return signed;
        }
    }
}
