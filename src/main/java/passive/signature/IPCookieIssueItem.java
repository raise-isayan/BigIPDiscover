package passive.signature;

/**
 *
 * @author isayan
 */
public class IPCookieIssueItem extends IPAddressIssueItem {

    private String encryptCookie = "";

    public String getEncryptCookie() {
        return this.encryptCookie;
    }

    /**
     * @param encryptCookie the encryptCookie to set
     */
    protected void setEncryptCookie(String encryptCookie) {
        this.encryptCookie = encryptCookie;
    }

}
