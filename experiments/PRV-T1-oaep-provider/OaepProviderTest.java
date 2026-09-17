import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * PRV-T1 (Lock section 6, harness section 16.3 #1): same OAEP transformation
 * string under SunJCE and Bouncy Castle -- do the MGF1 digests differ, and
 * does cross-decryption fail?
 *
 * Standalone experiment, not domain code. Prints raw facts only; no
 * interpretation happens here.
 */
public class OaepProviderTest {
    static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static void main(String[] args) throws Exception {
        System.out.println("java.version=" + System.getProperty("java.version"));
        System.out.println("java.vendor=" + System.getProperty("java.vendor"));
        System.out.println("java.vm.name=" + System.getProperty("java.vm.name"));

        Security.addProvider(new BouncyCastleProvider());
        System.out.println("BC provider registered: " + new BouncyCastleProvider().getVersionStr());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("RSA keypair generated: 2048 bits (explicit, not under test here)");

        Cipher sunEnc = Cipher.getInstance(TRANSFORMATION, "SunJCE");
        sunEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        System.out.println("SunJCE cipher provider (encrypt): " + sunEnc.getProvider().getName());
        printMgf1(sunEnc, "SunJCE encrypt");

        Cipher bcEnc = Cipher.getInstance(TRANSFORMATION, "BC");
        bcEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        System.out.println("BC cipher provider (encrypt): " + bcEnc.getProvider().getName());
        printMgf1(bcEnc, "BC encrypt");

        byte[] plaintext = "PRV-T1 test plaintext".getBytes("UTF-8");

        byte[] ctSun = sunEnc.doFinal(plaintext);
        byte[] ctBc = bcEnc.doFinal(plaintext);

        // same-provider round trip sanity check
        Cipher sunDec = Cipher.getInstance(TRANSFORMATION, "SunJCE");
        sunDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] ptSunSun = sunDec.doFinal(ctSun);
        System.out.println("SunJCE-encrypt -> SunJCE-decrypt: " + new String(ptSunSun, "UTF-8"));

        Cipher bcDec = Cipher.getInstance(TRANSFORMATION, "BC");
        bcDec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] ptBcBc = bcDec.doFinal(ctBc);
        System.out.println("BC-encrypt -> BC-decrypt: " + new String(ptBcBc, "UTF-8"));

        // cross-provider decryption
        System.out.println("--- cross-provider decryption ---");
        try {
            Cipher crossDec1 = Cipher.getInstance(TRANSFORMATION, "BC");
            crossDec1.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            byte[] pt = crossDec1.doFinal(ctSun);
            System.out.println("SunJCE-encrypt -> BC-decrypt: SUCCESS: " + new String(pt, "UTF-8"));
        } catch (Exception e) {
            System.out.println("SunJCE-encrypt -> BC-decrypt: FAILED: " + e.getClass().getName() + ": " + e.getMessage());
        }

        try {
            Cipher crossDec2 = Cipher.getInstance(TRANSFORMATION, "SunJCE");
            crossDec2.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            byte[] pt = crossDec2.doFinal(ctBc);
            System.out.println("BC-encrypt -> SunJCE-decrypt: SUCCESS: " + new String(pt, "UTF-8"));
        } catch (Exception e) {
            System.out.println("BC-encrypt -> SunJCE-decrypt: FAILED: " + e.getClass().getName() + ": " + e.getMessage());
        }

        // explicit MGF1-SHA-1 and MGF1-SHA-256 decrypt of the SunJCE ciphertext,
        // per Lock 6.1 P-3 methodology
        System.out.println("--- explicit MGF1 param decrypt of SunJCE ciphertext ---");
        tryExplicit(ctSun, kp, "SunJCE", MGF1ParameterSpec.SHA1, "MGF1-SHA-1");
        tryExplicit(ctSun, kp, "SunJCE", MGF1ParameterSpec.SHA256, "MGF1-SHA-256");
    }

    static void printMgf1(Cipher c, String label) throws Exception {
        try {
            OAEPParameterSpec spec = c.getParameters().getParameterSpec(OAEPParameterSpec.class);
            MGF1ParameterSpec mgf = (MGF1ParameterSpec) spec.getMGFParameters();
            System.out.println(label + ": digestAlgorithm=" + spec.getDigestAlgorithm()
                    + " mgfAlgorithm=" + spec.getMGFAlgorithm()
                    + " mgf1Digest=" + mgf.getDigestAlgorithm());
        } catch (Exception e) {
            System.out.println(label + ": could not read OAEPParameterSpec: " + e);
        }
    }

    static void tryExplicit(byte[] ct, KeyPair kp, String provider, MGF1ParameterSpec mgf, String label) {
        try {
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", mgf, javax.crypto.spec.PSource.PSpecified.DEFAULT);
            Cipher c = Cipher.getInstance(TRANSFORMATION, provider);
            c.init(Cipher.DECRYPT_MODE, kp.getPrivate(), spec);
            byte[] pt = c.doFinal(ct);
            System.out.println(label + " (" + provider + "): SUCCESS: " + new String(pt, java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.out.println(label + " (" + provider + "): FAILED: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }
}
