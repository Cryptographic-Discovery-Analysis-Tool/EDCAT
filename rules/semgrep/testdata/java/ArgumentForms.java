// Rule-test corpus for rules/semgrep/crypto-inventory-java.yaml.
//
// Not a crypto implementation and never executed -- it exists so the rules can
// be tested against every FORM an algorithm argument takes, including the forms
// that do not occur in any single real project. The point under test is the
// literal / non-literal partition: every crypto call site must be classified by
// exactly one of the two algorithm rules, so a call site can never silently
// produce no finding at all.
//
// Deliberately contains no key material and no real configuration.

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.net.ssl.SSLContext;

public class ArgumentForms {

    private static final String ALG = "AES/CBC/PKCS5Padding";

    /** Constant-propagated: statically determined, but not written at the call site. */
    public void constantPropagated() throws Exception {
        Cipher.getInstance(ALG);
    }

    /** Concatenation: not statically determined here. */
    public void concatenated(String mode) throws Exception {
        Cipher.getInstance("AES/" + mode);
    }

    /** Plain literal at the call site. */
    public void directLiteral() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
    }

    /** Value arrives from a method call -- the config-driven shape. */
    public void fromMethod(Config config) throws Exception {
        Cipher.getInstance(config.get());
    }

    /** Names a protocol, not an algorithm: must not populate an algorithm field. */
    public void protocolNotAlgorithm() throws Exception {
        SSLContext.getInstance("TLSv1.3");
    }

    /** Explicit provider argument: additive evidence on the same call site. */
    public void withExplicitProvider() throws Exception {
        Mac.getInstance("HmacSHA256", "SunJCE");
    }

    interface Config {
        String get();
    }
}
