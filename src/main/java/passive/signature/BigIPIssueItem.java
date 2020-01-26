package passive.signature;

import extend.util.IpUtil;
import java.text.ParseException;
import passive.IssueItem;
import passive.IssueItem;

/**
 *
 * @author isayan
 */
public class BigIPIssueItem extends IssueItem {

    public boolean isPrivateIP() {
        try {
            return IpUtil.isPrivateIP(this.ipAddr);
        } catch (ParseException ex) {
            return false;
        }
    }

    private boolean startsBIGipServer = false;
    
    public boolean startsBIGipServer() {
        return this.startsBIGipServer;
    }

    /**
     * @param startsBIGipServer the startsBIGipServer to set
     */
    protected void setStartsBIGipServer(boolean startsBIGipServer) {
        this.startsBIGipServer = startsBIGipServer;
    }
    
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
    
    private String ipAddr = "";
    
    public String getIPAddr() {
        return this.ipAddr;
    }

    /**
     * @param ipAddr the ipAddr to set
     */
    protected void setIPAddr(String ipAddr) {
        this.ipAddr = ipAddr;
    }
    
}
