package Encrypt;

import java.security.SecureRandom;

public class Utils {
    public static byte[] generateBytes(int sizeN){
        SecureRandom random = new SecureRandom();
        byte[] N = new byte[sizeN];
        random.nextBytes(N);
        return N;
    }
    
    public static byte[] XoR(byte[] text, byte[] key){

        if (text.length != key.length){
            return null;
        }

        byte[] result = new byte[key.length];


        for (int i = 0; i < key.length; i++){
            result[i] = (byte) (key[i] ^ text[i]);
        }

        return result;
    }
    public static byte[] concatArrays(byte[] ... arrays){ //Лучшая функция в Рунете (МОЯ) (Работает)
        int length = 0;
        for (byte[] array : arrays){
            length += array.length;
        }
        byte[] out = new byte[length];
        length = 0;
        for (byte[] array : arrays){
            System.arraycopy(array, 0, out, length, array.length);
            length += array.length;
        }
        return out;
    }
    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
}
