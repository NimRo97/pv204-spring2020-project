package applet;

import javacard.security.*;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javacardx.crypto.Cipher;

public class SimpleApplet extends javacard.framework.Applet
{
    private int trace = 2;

    final private static byte pin[] = {0x31,0x32,0x33,0x34};
    final private static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    private MessageDigest hash = null;
    private X9ECParameters curve = null;
    private ECDomainParameters ecdp = null;
    private SecureRandom random = null;
    private ECKeyPairGenerator gen = null;
    private AESKey aesKey = null;
    private Cipher aesCipher = null;

    private byte[] secret = null;
    private byte[] secretmod = null;
    private byte[] secrethash = null;
    private byte[] decinput = null;
    private byte[] sentencinput = null;

    protected SimpleApplet(byte[] buffer, short offset, byte length)
    {
        hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
        secret = JCSystem.makeTransientByteArray((short)33, JCSystem.CLEAR_ON_DESELECT);
        secretmod = JCSystem.makeTransientByteArray((short)33, JCSystem.CLEAR_ON_DESELECT);
        secrethash = JCSystem.makeTransientByteArray((short)33, JCSystem.CLEAR_ON_DESELECT);

        decinput = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        sentencinput = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);

        curve = ECNamedCurveTable.getByName("secp256r1");
        ecdp = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(),
                curve.getH(), curve.getSeed());

        //Reference https://tools.ietf.org/id/draft-irtf-cfrg-spake2-04.xml
        //Reference https://gist.github.com/wuyongzheng/0e2ed6d8a075153efcd3
        random = new SecureRandom();
        gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ecdp, random));

        aesKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        new SimpleApplet(bArray, bOffset, bLength);
    }

    public boolean select()
    {
        clearData();
        return true;
    }

    public void deselect()
    {
        clearData();
    }

    private void clearData()
    {
        Util.arrayFillNonAtomic(secret, (short)0, (short)secret.length, (byte)0);
        Util.arrayFillNonAtomic(secretmod, (short)0, (short)secretmod.length, (byte)0);
        Util.arrayFillNonAtomic(secrethash, (short)0, (short)secrethash.length, (byte)0);

        Util.arrayFillNonAtomic(decinput, (short)0, (short)decinput.length, (byte)0);
        Util.arrayFillNonAtomic(sentencinput, (short)0, (short)sentencinput.length, (byte)0);
    }

    public void process(APDU apdu) throws ISOException
    {
        byte[] apduBuffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        try
        {
            if (selectingApplet())
                return;

            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET)
            {
                switch (apduBuffer[ISO7816.OFFSET_INS])
                {
                    case (byte) 0xD1: pinandecdhchannel(apdu, len); return;
                    case (byte) 0xD2: sharedsecret(apdu); return;
                    case (byte) 0xD3: aescommunication(apdu); return;
                    default:    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
                }
            }
            else
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        catch (NoSuchAlgorithmException ex)
        {
            Logger.getLogger(SimpleApplet.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch (Exception ex)
        {
            Logger.getLogger(SimpleApplet.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void pinandecdhchannel(APDU apdu, short len) throws NoSuchAlgorithmException
    {
        byte[] apdubuf = apdu.getBuffer();
        //Receives T = X + wM
        short dataLen = apdu.getIncomingLength();
        byte t[]=new byte[dataLen];
        System.arraycopy(apdubuf,ISO7816.OFFSET_CDATA, t,(short)0,dataLen);

        AsymmetricCipherKeyPair CardPair = gen.generateKeyPair();
        ECPublicKeyParameters CardPublic = (ECPublicKeyParameters) CardPair.getPublic();
        ECPrivateKeyParameters CardPrivate = (ECPrivateKeyParameters) CardPair.getPrivate();

        //Secret = y(T - wM)
        ECPoint Y = CardPublic.getQ();
        BigInteger y = CardPrivate.getD();
        long num = Long.parseLong(new String(pin));
        BigInteger w = BigInteger.valueOf(num);
        ECPoint N = ecdp.getCurve().decodePoint(Hex.decode("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));
        ECPoint M = ecdp.getCurve().decodePoint(Hex.decode("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
        ECPoint T = ecdp.getCurve().decodePoint(t);
        ECPoint sec = T.subtract(M.multiply(w)).multiply(y);
        secret = sec.getEncoded(true);

        //Transmits S = Y + wN
        ECPoint S = N.multiply(w).add(Y);
        byte[] sentS = S.getEncoded(true);
        System.arraycopy(sentS, (short)0, apdubuf,ISO7816.OFFSET_CDATA, sentS.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)sentS.length);
    }

    public void sharedsecret(APDU apdu) throws Exception
    {
        byte[] apduBuf = apdu.getBuffer();

        System.out.println();
        System.out.print("Shared Secret K (CARD): ");
        for (byte b: secret) System.out.print(String.format("%02X", b));
        System.out.println();

        System.arraycopy(secret, 0, secretmod, 0, secret.length);
        hash.doFinal(secretmod, (short)0, (short)secretmod.length, secrethash, (short)0);

        Util.arrayCopyNonAtomic(secret, (short) 0, apduBuf, ISO7816.OFFSET_CDATA, (short)secret.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)secret.length);
    }

    private void aescommunication(APDU apdu)
    {
        byte[] apduBuf = apdu.getBuffer();

        byte[] input = new byte[16];
        new Random().nextBytes(input);
        byte[] encinput = Arrays.copyOfRange(apduBuf, 5, 21);

        System.out.println();
        System.out.print("Encrypted Input (from HOST): ");
        for (byte b: encinput) System.out.print(String.format("%02X", b));
        System.out.println();

        aesKey.setKey(secretmod,(short)0);
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(encinput, (short)0, (short)encinput.length, decinput, (short)0);

        System.out.print("Decrypted Input (from HOST): ");
        for (byte b: decinput) System.out.print(String.format("%02X", b));
        System.out.println();

        System.out.println();
        System.out.print("Input (CARD): ");
        for (byte b: input) System.out.print(String.format("%02X", b));
        System.out.println();

        //Modifying Secret Key After Every Trace
        //Secret Key = Shift Right((Secret Key XOR Hash(Secret Key)), 1)
        BigInteger sm = new BigInteger(secretmod);
        BigInteger sh = new BigInteger(secrethash);
        BigInteger sk = sm.xor(sh).shiftRight(5);
        secretmod = sk.toByteArray();

        aesKey.setKey(secretmod,(short)0);
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        aesCipher.doFinal(input, (short)0, (short)input.length, sentencinput, (short)0);

        System.out.print("Encrypted Input (CARD): ");
        for (byte b: sentencinput) System.out.print(String.format("%02X", b));
        System.out.println();

        System.out.print("Secret Key (CARD): ");
        for (byte b: secretmod) System.out.print(String.format("%02X", b));
        System.out.println();

        System.out.println("\n********************Trace [" + trace + "] CARD TO HOST********************\n");

        Util.arrayCopyNonAtomic(sentencinput, (short) 0, apduBuf, ISO7816.OFFSET_CDATA, (short)sentencinput.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)sentencinput.length);

        //Modifying Secret Key After Every Trace
        //Secret Key = Shift Right((Secret Key XOR Hash(Secret Key)), 1)
        sm = new BigInteger(secretmod);
        sh = new BigInteger(secrethash);
        sk = sm.xor(sh).shiftRight(10);
        secretmod = sk.toByteArray();

        trace = trace + 2;
    }
}
