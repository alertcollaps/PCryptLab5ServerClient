package Manager;


public class KeyManager {
    static final int sizePad = 65;
    public static byte[] dataPadding(byte[] pw){
        if (pw.length >= sizePad){
            throw new RuntimeException("Password is too long");
        }
        byte[] out = new byte[sizePad];
        System.arraycopy(pw, 0, out, 0, pw.length);
        int pad = sizePad - pw.length;
        for (int i = pw.length; i < sizePad; i++){
            out[i] = (byte) pad;
        }
        return out;
    }
    public static byte[] removePadding(byte[] pw){
        int pad = pw[pw.length - 1];
        if (pad >= sizePad){
            throw new RuntimeException("Bad padding");
        }
        for (int i = pw.length - 1; i >= sizePad - pad; i--){
            if (pw[i] != pad){
                throw new RuntimeException("Bad padding");
            }
        }
        byte[] out = new byte[pw.length - pad];
        System.arraycopy(pw, 0, out, 0, out.length);
        return out;
    }

    public static void main(String[] args) {
        String pass = "Secret";
        byte[] passBytes = pass.getBytes();
        byte[] passPaddBytes = dataPadding(passBytes);
        System.out.println(new String(passPaddBytes));
        System.out.println(new String(removePadding(passPaddBytes)));
    }
}
