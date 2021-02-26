package passive.signature;

import extension.helpers.IpUtil;
import java.text.ParseException;
import passive.IssueItem;

/**
 *
 * @author isayan
 */
public class IPAddressIssueItem extends IssueItem {

    public boolean isPrivateIP() {
        try {
            return IpUtil.isPrivateIP(this.ipAddr);
        } catch (ParseException ex) {
            return false;
        }
    }

    public boolean isLinkLocalIP() {
        try {
            return IpUtil.isLinkLocalIP(this.ipAddr);
        } catch (ParseException ex) {
            return false;
        }
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
