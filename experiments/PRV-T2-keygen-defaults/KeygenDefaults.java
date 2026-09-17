import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * PRV-T2 (Lock section 6, harness section 16.3 #2): unsized
 * KeyGenerator("AES") / KeyPairGenerator("RSA"|"EC") on the pinned JDK build.
 * Records the actual default size/curve and the provider from getProvider().
 *
 * Standalone experiment, not domain code. Prints raw facts only.
 */
public class KeygenDefaults {
    public static void main(String[] args) throws Exception {
        System.out.println("java.version=" + System.getProperty("java.version"));
        System.out.println("java.vendor=" + System.getProperty("java.vendor"));
        System.out.println("java.vm.name=" + System.getProperty("java.vm.name"));

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey aesKey = kg.generateKey();
        System.out.println("AES unsized: keyLengthBits=" + (aesKey.getEncoded().length * 8)
                + " provider=" + kg.getProvider().getName());

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        KeyPair rsaKp = rsaKpg.generateKeyPair();
        RSAPublicKey rsaPub = (RSAPublicKey) rsaKp.getPublic();
        System.out.println("RSA unsized: modulusBits=" + rsaPub.getModulus().bitLength()
                + " provider=" + rsaKpg.getProvider().getName());

        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        KeyPair ecKp = ecKpg.generateKeyPair();
        ECPublicKey ecPub = (ECPublicKey) ecKp.getPublic();
        System.out.println("EC unsized: fieldSizeBits=" + ecPub.getParams().getCurve().getField().getFieldSize()
                + " curveOrderBits=" + ecPub.getParams().getOrder().bitLength()
                + " provider=" + ecKpg.getProvider().getName());
    }
}
