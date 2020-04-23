/*
 * Copyright 2020 Matěj Grabovský, Nomit Sharma, Milan Šorf

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package simpleapdu;

import applet.SimpleApplet;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;

//Note: If simulator cannot be started try adding "-noverify" JVM parameter

public class SimpleAPDU {

    private static byte APPLET_AID[] = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x06, (byte) 0xC9, (byte) 0xAA, (byte) 0x4E, (byte) 0x15, (byte) 0xB3, (byte) 0xF6, (byte) 0x7F};
    private static CardMngr cardManager = new CardMngr();
    private byte pinHash[] = null;
    private byte[] secret = new byte[33];
    private byte[] secrethash = new byte[20];

    MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
    AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

    public static void main(String[] args)
    {
        try
        {
            String presetPIN;
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

            System.out.println("**** Applet installation phase ****");
            do {
                System.out.print("Pre-set PIN on the card: ");
                presetPIN = br.readLine();
            } while (!validatePin(presetPIN));

            // Send pre-set PIN for installation.
            byte[] installData = presetPIN.getBytes();
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
            System.out.println("Applet successfully installed.");

            SimpleAPDU main = new SimpleAPDU();
            main.pin();
        }
        catch (Exception ex)
        {
            System.out.println("Exception : " + ex);
        }
    }

    private static boolean validatePin(String pin) {
        if (!pin.matches("^[0-9]{4}$")) {
            System.out.println("Invalid PIN. Exactly Four Digits Required.");
            return false;
        }

        return true;
    }

    private void pin() throws Exception
    {
        System.out.println("\n**** Host application interaction ****");
        int attempts = 0;
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println();

        while(attempts != 4)
        {
            System.out.print("Enter PIN (HOST): ");
            String pin = br.readLine();

            if (!validatePin(pin))
            {
                attempts++;
            }
            else
            {
                attempts = 4;
                pinHash = new byte[20];
                hash.doFinal(pin.getBytes(), (short)0, (short)pin.getBytes().length, pinHash, (short)0);
                ecdhchannel();
            }
        }

        System.out.println();
        System.out.print("Closing Session...");
        System.out.println();
    }

    private void ecdhchannel() throws Exception
    {
        //Reference https://tools.ietf.org/id/draft-irtf-cfrg-spake2-04.xml
        //Reference https://gist.github.com/wuyongzheng/0e2ed6d8a075153efcd3
        X9ECParameters curve = ECNamedCurveTable.getByName("secp256r1");
        ECDomainParameters ecdp = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());

        final SecureRandom random = new SecureRandom();
        final ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ecdp, random));

        AsymmetricCipherKeyPair HostPair = gen.generateKeyPair();
        ECPublicKeyParameters HostPublic = (ECPublicKeyParameters) HostPair.getPublic();
        ECPrivateKeyParameters HostPrivate = (ECPrivateKeyParameters) HostPair.getPrivate();

        ECPoint X = HostPublic.getQ();
        BigInteger x = HostPrivate.getD();

        BigInteger w = new BigInteger(pinHash);
        ECPoint N = ecdp.getCurve().decodePoint(Hex.decode("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));
        ECPoint M = ecdp.getCurve().decodePoint(Hex.decode("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
        ECPoint t = M.multiply(w).add(X);

        //Transmits T = X + wM
        byte[] T = t.getEncoded(true);
        byte sentT[] = new byte[CardMngr.HEADER_LENGTH + T.length];
        sentT[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        sentT[CardMngr.OFFSET_INS] = (byte) 0xD1;//
        sentT[CardMngr.OFFSET_P1] = (byte) 0x01;
        sentT[CardMngr.OFFSET_P2] = (byte) 0x00;
        sentT[CardMngr.OFFSET_LC] = (byte) T.length;
        if(T.length!=0)
            System.arraycopy(T, 0, sentT, CardMngr.OFFSET_DATA, T.length);

        //Receives S = Y + wN
        byte[] receivedS = cardManager.sendAPDUSimulator(sentT);

        //Secret = x(S - wN)
        int len = receivedS.length - 2;
        byte[] s = new byte[len];
        System.arraycopy(receivedS, (short)0, s,(short)0, (short)len);
        ECPoint S = ecdp.getCurve().decodePoint(s);
        ECPoint sec = S.subtract(N.multiply(w)).multiply(x);
        secret = sec.getEncoded(true);

        hash.doFinal(secret, (short)0, (short)secret.length, secrethash, (short)0);
        aesKey.setKey(secret,(short)0);

        verifysecret();
    }

    private void verifysecret() throws Exception
    {
        System.out.println();
        System.out.print("Shared Secret K (HOST): ");
        for (byte b: secret) System.out.print(String.format("%02X", b));
        System.out.println();

        byte getsecret[] = new byte[CardMngr.HEADER_LENGTH];
        getsecret[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        getsecret[CardMngr.OFFSET_INS] = (byte) 0xD2;
        getsecret[CardMngr.OFFSET_P1] = (byte) 0x01;
        getsecret[CardMngr.OFFSET_P2] = (byte) 0x00;
        getsecret[CardMngr.OFFSET_LC] = (byte) 0x00;
        byte[] response = cardManager.sendAPDUSimulator(getsecret);
        byte[] appletEnc = Arrays.copyOfRange(response, 0, response.length - 2);

        byte[] appletDec = new byte[33];
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        short lenDec = 0;

        try
        {
            lenDec = aesCipher.doFinal(appletEnc, (short)0, (short)(response.length - 2),
                    appletDec, (short)0);
        }
        catch (CryptoException e)
        {
            System.out.println("\nPIN incorrect. Exiting...");
            System.exit(1);
        }

        System.out.println(String.format("\n+++ Decrypted %d bytes: %s",
                lenDec, CardMngr.bytesToHex(appletDec)));

        if(lenDec != 32 || !Arrays.equals(appletDec, 0, 32, secret, 0, 32))
        {
            System.out.println("\nPIN incorrect. Exiting...");
            System.exit(1);
        }

        System.out.println("\nPIN Correct. Establishing Session...");
        aescommunication();
    }

    private void aescommunication() throws Exception
    {
        int trace = 1;

        while(trace!=11)
        {
            byte[] input = new byte[16];
            new Random().nextBytes(input);
            byte[] encinput = new byte[16];
            byte[] decinput = new byte[16];

            System.out.println();
            System.out.print("Input (HOST): ");
            for (byte b: input) System.out.print(String.format("%02X", b));
            System.out.println();

            aesKey.setKey(secret,(short)0);
            aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
            aesCipher.doFinal(input, (short)0, (short)input.length, encinput, (short)0);

            System.out.print("Encrypted Input (HOST): ");
            for (byte b: encinput) System.out.print(String.format("%02X", b));
            System.out.println();

            System.out.print("Secret Key (HOST): ");
            for (byte b: secret) System.out.print(String.format("%02X", b));
            System.out.println();

            System.out.println();System.out.println("********************Trace [" + trace + "] HOST TO CARD********************");System.out.println();

            byte sentencinput[] = new byte[CardMngr.HEADER_LENGTH + encinput.length];
            sentencinput[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            sentencinput[CardMngr.OFFSET_INS] = (byte) 0xD3;
            sentencinput[CardMngr.OFFSET_P1] = (byte) 0x01;
            sentencinput[CardMngr.OFFSET_P2] = (byte) 0x00;
            sentencinput[CardMngr.OFFSET_LC] = (byte) encinput.length;
            System.arraycopy(encinput, 0, sentencinput, 5, encinput.length);
            byte[] receivedinput = cardManager.sendAPDUSimulator(sentencinput);
            byte[] receivedinputCard = Arrays.copyOfRange(receivedinput, 0, input.length);

            //Modifying Secret Key After Every Trace
            //Secret Key = Shift Right((Secret Key XOR Hash(Secret Key)), 1)
            BigInteger sm = new BigInteger(secret);
            BigInteger sh = new BigInteger(secrethash);
            BigInteger sk = sm.xor(sh).shiftRight(5);
            secret = sk.toByteArray();

            System.out.println();
            System.out.print("Encrypted Input (from CARD): ");
            for (byte b: receivedinputCard) System.out.print(String.format("%02X", b));
            System.out.println();

            aesKey.setKey(secret,(short)0);
            aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
            aesCipher.doFinal(receivedinputCard, (short)0, (short)decinput.length, decinput, (short)0);

            System.out.print("Decrypted Input (from CARD): ");
            for (byte b: decinput) System.out.print(String.format("%02X", b));
            System.out.println();

            //Modifying Secret Key After Every Trace
            //Secret Key = Shift Right((Secret Key XOR Hash(Secret Key)), 1)
            sm = new BigInteger(secret);
            sh = new BigInteger(secrethash);
            sk = sm.xor(sh).shiftRight(10);
            secret = sk.toByteArray();

            trace = trace + 2;
        }
    }
}
