package passive.signature;

import extension.burp.scanner.IssueItem;
import extension.helpers.IpUtil;

/**
 *
 * @author isayan
 */
public class IPAddressIssueItem extends IssueItem {

    public boolean isPrivateIP() {
        return IpUtil.isPrivateIP(this.ipAddr);
    }

    public boolean isLinkLocalIP() {
        return IpUtil.isLinkLocalIP(this.ipAddr);
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
