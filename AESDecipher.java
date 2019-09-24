import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class AESDecipher {

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public static SecretKeySpec getSecretKey(String passwd) throws Exception {
        //byte[] dataBytes = passwd.getBytes();
        byte[] dataBytes = toByteArray(passwd);

        // MessageDigest md = MessageDigest.getInstance("SHA-256");
        // md.update(dataBytes, 0, passwd.length());
        // byte[] mdbytes = md.digest();

        //return new SecretKeySpec(Arrays.copyOfRange(mdbytes, 0, 16), "AES");
        return new SecretKeySpec(dataBytes, "AES");
    }

    public static void main(String[] args) throws Exception {
        SecretKeySpec skeySpec = getSecretKey(args[0]);


        String input = args[1];
        System.out.println(input);
        input = input.substring(0, 32);
        byte[] iv = toByteArray(input);
        
        IvParameterSpec ivp = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivp);

        byte[] deciphered = cipher.doFinal(toByteArray(args[1].substring(32)));
        System.out.println("Mensagem cifrada: " + new String(deciphered));

    }
}

//4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81