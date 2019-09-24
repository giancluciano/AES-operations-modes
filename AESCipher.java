import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AESCipher {
    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public static SecretKeySpec getSecretKey(String passwd) throws Exception {
        byte[] dataBytes = passwd.getBytes();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(dataBytes, 0, passwd.length());
        byte[] mdbytes = md.digest();

        return new SecretKeySpec(Arrays.copyOfRange(mdbytes, 0, 16), "AES");
    }

    public static void main(String[] args) throws Exception {
        SecretKeySpec skeySpec = getSecretKey(args[0]);

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

        byte[] encrypted = cipher.doFinal(args[1].getBytes());
        System.out.println("Mensagem cifrada: " + toHexString(encrypted));

    }
}