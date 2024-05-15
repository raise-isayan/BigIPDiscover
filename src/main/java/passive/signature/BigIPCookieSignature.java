package passive.signature;

import extension.burp.Severity;
import extension.burp.scanner.SignatureItem;

/**
 *
 * @author isayan
 */
public class BigIPCookieSignature extends SignatureItem {

    public BigIPCookieSignature() {
        super(new BigIPCookieScan(), Severity.LOW);
    }

    @Override
    public char getSortOrder() {
        return '5';
    }

}
