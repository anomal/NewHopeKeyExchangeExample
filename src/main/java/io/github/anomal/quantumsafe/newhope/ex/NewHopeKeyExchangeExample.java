package io.github.anomal.quantumsafe.newhope.ex;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.pqc.crypto.newhope.NHAgreement;
import org.bouncycastle.pqc.crypto.newhope.NHExchangePairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;

import java.security.SecureRandom;
import java.util.Base64;

public class NewHopeKeyExchangeExample {

    public static void main(String[] args) {
        // Alice does this
        NHKeyPairGenerator nhKeyPairGenerator = new NHKeyPairGenerator();
        nhKeyPairGenerator.init(new KeyGenerationParameters(new SecureRandom(), 1024));
        AsymmetricCipherKeyPair aliceKeyPair = nhKeyPairGenerator.generateKeyPair();
        NHPublicKeyParameters alicePublicKey = (NHPublicKeyParameters) aliceKeyPair.getPublic();
        String alicePubKey = Base64.getEncoder().encodeToString(alicePublicKey.getPubData());
        System.out.println("Alice sends 'alicePubKey' to Bob.");
        System.out.println("alicePubKey: " + alicePubKey);
        System.out.println();

        // Bob does this
        NHPublicKeyParameters fromAlice = new NHPublicKeyParameters(Base64.getDecoder().decode(alicePubKey));
        System.out.println("Bob calculates shared value and value to send to Alice.");
        ExchangePair bobSecretExchangePair = new NHExchangePairGenerator(new SecureRandom()).generateExchange(fromAlice);
        byte[] sharedValueAsPerBob = bobSecretExchangePair.getSharedValue();
        String bobSharedVal = Base64.getEncoder().encodeToString(sharedValueAsPerBob);
        System.out.println("Bob calculates shared value: " + bobSharedVal);
        NHPublicKeyParameters keyExchangePublic = (NHPublicKeyParameters) (bobSecretExchangePair.getPublicKey());
        String forAlice = Base64.getEncoder().encodeToString(keyExchangePublic.getPubData());
        System.out.println("Bob sends 'forAlice' to Alice.");
        System.out.println("forAlice: " + forAlice);
        System.out.println();

        // Alice does this
        NHPublicKeyParameters fromBob = new NHPublicKeyParameters(Base64.getDecoder().decode(forAlice));
        NHAgreement nhAgreement = new NHAgreement();
        nhAgreement.init(aliceKeyPair.getPrivate());
        byte[] sharedValueAsPerAlice = nhAgreement.calculateAgreement(fromBob);
        String aliceSharedVal = Base64.getEncoder().encodeToString(sharedValueAsPerAlice);
        System.out.println("Alice calculates shared value: " + aliceSharedVal);
        System.out.println();

        System.out.println("aliceSharedVal equals bobSharedVal is: " + aliceSharedVal.equals(bobSharedVal));
    }

}
