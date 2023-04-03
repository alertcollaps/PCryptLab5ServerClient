package Encrypt;

public class KeyGenerators{
    final static int saltLength = 64;
    final static byte[] binVectorForHmac = {
        -26, 59, -20, 39, -46, 38, -100, 71, 39, 64, 33, 127, 84, -16, 62, -46, 109, -97, 24, 28, 45, -80, -51, -61, -115, 68, 124, -116, -70, 56, 43, 14
    };

    final static byte[] binVectorForAEAD = {
        -88, 21, 121, -24, -35, 56, -32, 43, 57, -34, -24, -111, -105, -21, 127, 117, -44, -63, -58, 112, -66, -123, 89, 85, -22, -68, -4, 85, 7, 34, 21, 2
    };

    public static byte[] generateSalt(){
        return Utils.generateBytes(saltLength);
    }
    
    private static byte[] getMainKey(byte[] pw, byte[] salt){
        return Gost.PBKDF2(pw, salt, 1000);
    }
    
    public static byte[] getHmacKey(byte[] pw, byte[] salt){
        return Gost.HmacFunc(getMainKey(pw, salt), binVectorForHmac);
    }

    public static byte[] getAEADKey(byte[] pw, byte[] salt){
        return Gost.HmacFunc(getMainKey(pw, salt), binVectorForAEAD);
    }

    public static void main(String[] args) {
        
        byte[] gen = Utils.generateBytes(32);
        /* 
        System.out.print("{");
        
        for (byte i : gen){
            System.out.print(i + ", ");
        }
        System.out.print("}");
        */
        long start = System.currentTimeMillis();
        getMainKey(gen, gen);
        long diff = System.currentTimeMillis() - start;
        System.out.println("Время выполнения PBKDF2: " + diff + " миллисекунд");
    }
}