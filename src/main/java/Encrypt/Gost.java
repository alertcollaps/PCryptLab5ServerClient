package Encrypt;

import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import org.bouncycastle.crypto.modes.GCMBlockCipher;


import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.GOST3411Digest;

import org.bouncycastle.crypto.engines.GOST3412_2015Engine;

public class Gost {
    static final int MAC_SIZE_BITS = 128;
    public static byte[] PBKDF2(byte[] pw, byte[] salt, int d){
        byte[] x0 = HmacFunc(pw, salt);
        byte[][] res = new byte[d][x0.length];
        res[0] = x0;
        byte[] out = new byte[x0.length];
        System.arraycopy(x0, 0, out, 0, x0.length);
    
        for (int i = 1; i < d; i++){
            x0 = HmacFunc(salt, res[i-1]);
            out = Utils.XoR(x0, out);
        }
        return out;
    }
    public static byte[] HmacFunc(byte[] key, byte[] data){
    
        HMac gMac= new HMac(new GOST3411Digest());

        
        gMac.init(new KeyParameter(key));
    
        gMac.update(data, 0, data.length);
        byte[] mac = new byte[gMac.getMacSize()];
    
        gMac.doFinal(mac, 0);
        return mac;
    }

    public static byte[] encrypt(byte[] key, byte[] data) throws IllegalStateException, InvalidCipherTextException {
        BlockCipher engine = new GOST3412_2015Engine();
        
        AEADBlockCipher cipher = new GCMBlockCipher(engine);
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[12];
        random.nextBytes(ivBytes);
        
        cipher.init(true, new AEADParameters(new KeyParameter(key), MAC_SIZE_BITS, ivBytes));
        
        
        byte[] enc = new byte[cipher.getOutputSize(data.length)];
        int res = cipher.processBytes(data, 0, data.length, enc, 0);
        cipher.doFinal(enc, res);
        byte[] ivPlusCipherText = new byte[ivBytes.length+enc.length];
        System.arraycopy(ivBytes, 0, ivPlusCipherText, 0, ivBytes.length);
        System.arraycopy(enc, 0, ivPlusCipherText, ivBytes.length, enc.length);
        return ivPlusCipherText;
    }

    public static byte[] decrypt(byte[] key, byte[] data) throws IllegalStateException, InvalidCipherTextException {
        BlockCipher engine = new GOST3412_2015Engine();
        
        AEADBlockCipher cipher = new GCMBlockCipher(engine);
        
        byte[] ivBytes = new byte[12];
        System.arraycopy(data, 0, ivBytes, 0, ivBytes.length);

        byte[] cipherTextBytes = new byte[data.length-ivBytes.length];
        System.arraycopy(data, ivBytes.length, cipherTextBytes, 0, cipherTextBytes.length);
        
        cipher.init(false, new AEADParameters(new KeyParameter(key), MAC_SIZE_BITS, ivBytes));
        
        
        byte[] dec = new byte[cipher.getOutputSize(cipherTextBytes.length)];
        int res = cipher.processBytes(cipherTextBytes, 0, cipherTextBytes.length, dec, 0);
        cipher.doFinal(dec, res);
        
        return dec;
    }
   

    public static void main(String[] args) {
        byte[] key = new byte[32];
        byte[] data = "hello".getBytes();
        //byte[] hmac = HmacFunc(key, data);
        byte[] enc = null;
        byte[] dec = null;
        try{
            enc = encrypt(key, data);
            dec = decrypt(key, enc);
        } catch (Exception e){
            e.printStackTrace();
        }
        
        System.out.println(new String(dec));
    }
}
