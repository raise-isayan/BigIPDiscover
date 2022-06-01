package passive.signature;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.ITab;
import extension.burp.Confidence;
import extension.burp.IPropertyConfig;
import extension.burp.NotifyType;
import extension.burp.ScannerCheckAdapter;
import extension.burp.Severity;
import extension.helpers.StringUtil;
import extension.helpers.IpUtil;
import extension.helpers.json.JsonUtil;
import java.awt.Component;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.URL;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import passive.IssueItem;
import passive.SignatureScanBase;

/**
 *
 * @author isayan
 */

public class BigIPCookieScan extends SignatureScanBase<BigIPIssueItem> implements ITab, IPropertyConfig {
    private final static Logger logger = Logger.getLogger(BigIPCookieScan.class.getName());

    public final static String SIGNATURE_PROPERTY = "bigipCookieProperty";

    private final BigIPCookieTab tabBigIPCookie = new BigIPCookieTab();

    public BigIPCookieScan() {
        super("BIG-IP Cookie Discloses IP Address");
        this.tabBigIPCookie.addPropertyChangeListener(this.newPropertyChangeListener());
    }

    public final PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (SIGNATURE_PROPERTY.equals(evt.getPropertyName())) {
                    BigIPCookieProperty bigIPCookie = tabBigIPCookie.getProperty();
                    property.setProperty(bigIPCookie);
                }
            }
        };
    }

    @Override
    public IScannerCheck passiveScanCheck() {
        return new ScannerCheckAdapter() {
            @Override
            public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
                ArrayList<IScanIssue> issues = new ArrayList<>();
                // Response判定
                if (property.getScanResponse() && baseRequestResponse.getResponse() != null) {
                    issues.addAll(makeIssueList(false, baseRequestResponse, parseMessage(false, baseRequestResponse.getResponse())));
                }
                // Request判定
                if (issues.isEmpty() && property.getScanRequest() && baseRequestResponse.getRequest() != null) {
                    issues.addAll(makeIssueList(true, baseRequestResponse, parseMessage(true, baseRequestResponse.getRequest())));
                }
                if (issues.isEmpty()) {
                    return null;
                } else {
                    return issues;
                }
            }

            public List<IScanIssue> makeIssueList(boolean messageIsRequest, IHttpRequestResponse baseRequestResponse, List<BigIPIssueItem> issueList) {
                List<BigIPIssueItem> markList = new ArrayList<>();
                for (int i = 0; i < issueList.size(); i++) {
                    BigIPIssueItem item = issueList.get(i);
                    // Private IP Only にチェックがついていてPrivate IPで無い場合はスキップ
                    if (property.isDetectionPrivateIP() && !(item.isPrivateIP() || item.isLinkLocalIP())) {
                        continue;
                    }
                    markList.add(item);
                }
                List<IScanIssue> issues = new ArrayList<>();
                if (markList.isEmpty()) {
                    return issues;
                }
                IHttpRequestResponseWithMarkers applyMarks = applyMarkers(baseRequestResponse, markList);
                issues.add(makeScanIssue(applyMarks, markList));
                return issues;
            }

        };
    }

    @Override
    public IScanIssue makeScanIssue(IHttpRequestResponse messageInfo, List<BigIPIssueItem> issueItem) {

        return new IScanIssue() {

            public BigIPIssueItem getItem() {
                if (issueItem.isEmpty()) {
                    return null;
                } else {
                    return issueItem.get(0);
                }
            }

            @Override
            public URL getUrl() {
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                return reqInfo.getUrl();
            }

            @Override
            public String getIssueName() {
                return BigIPCookieScan.this.getIssueName();
            }

            @Override
            public int getIssueType() {
                /**
                 * https://portswigger.net/knowledgebase/issues/ Extension
                 * generated issue
                 */
                return 0x08000000;
            }

            @Override
            public String getSeverity() {
                IssueItem item = getItem();
                return item.getServerity().toString();
            }

            @Override
            public String getConfidence() {
                IssueItem item = getItem();
                return item.getConfidence().toString();
            }

            @Override
            public String getIssueBackground() {
                final String ISSUE_BACKGROUND = "\r\n"
                        + "<h4>Examples:</h4>"
                        + "<ul>"
                        + "  <li>BIGipServer<pool_name>=1677787402.36895.0000</li>"
                        + "  <li>BIGipServer<pool_name>=vi20010112000000000000000000000030.20480</li>"
                        + "  <li>BIGipServer<pool_name>=rd5o00000000000000000000ffffc0000201o80</li>"
                        + "  <li>BIGipServer<pool_name>=rd3o20010112000000000000000000000030o80</li>"
                        + "</ul>"
                        + "<h4>Reference:</h4>"
                        + "<ul>"
                        + "  <li><a href=\"https://www.owasp.org/index.php/SCG_D_BIGIP\">https://www.owasp.org/index.php/SCG_D_BIGIP</a></li>"
                        + "  <li><a href=\"https://support.f5.com/csp/article/K6917\">https://support.f5.com/csp/article/K6917</a></li>"
                        + "</ul>";
                return ISSUE_BACKGROUND;
            }

            @Override
            public String getRemediationBackground() {
                return null;
            }

            @Override
            public String getIssueDetail() {
                StringBuilder buff = new StringBuilder();
                buff.append("<h4>IP Address:</h4>");
                for (BigIPIssueItem markIP : issueItem) {
                    String cookieType = markIP.isMessageIsRequest() ? "Cookie" : "Set-Cookie";
                    buff.append("<div>");
                    buff.append("<ul>");
                    buff.append("<li>");
                    buff.append(String.format("%s: %s", cookieType, markIP.getCaptureValue()));
                    buff.append("</li>");
                    buff.append("<li>");
                    buff.append(String.format("ip address: %s", markIP.getIPAddr()));
                    buff.append("</li>");
                    if (markIP.isLinkLocalIP()) {
                        buff.append("<li>");
                        buff.append(String.format("Link local IP: %s", markIP.isLinkLocalIP()));
                        buff.append("</li>");
                    }
                    else {
                        buff.append("<li>");
                        buff.append(String.format("Private IP: %s", markIP.isPrivateIP()));
                        buff.append("</li>");
                    }

                    buff.append("</ul>");
                    buff.append("</div>");
                }
                return buff.toString();
            }

            @Override
            public String getRemediationDetail() {
                return null;
            }

            @Override
            public IHttpRequestResponse[] getHttpMessages() {
                return new IHttpRequestResponse[]{messageInfo};
            }

            @Override
            public IHttpService getHttpService() {
                return messageInfo.getHttpService();
            }
        };

    }

    public List<BigIPIssueItem> parseMessage(boolean messageIsRequest, byte[] message) {
        List<BigIPIssueItem> cookieIPList = new ArrayList<>();
        // Response判定
        if (!messageIsRequest) {
            // ヘッダのみ抽出（逆に遅くなってるかも？）
            IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(message);
            byte resHeader[] = Arrays.copyOfRange(message, 0, resInfo.getBodyOffset());
            cookieIPList.addAll(parseHeader(false, resHeader));
        }
        // Request判定
        if (messageIsRequest && message != null) {
            // ヘッダのみ抽出（逆に遅くなってるかも？）
            IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(message);
            byte reqHeader[] = Arrays.copyOfRange(message, 0, reqInfo.getBodyOffset());
            cookieIPList.addAll(parseHeader(true, reqHeader));
        }
        return cookieIPList;
    }

    private final static Pattern REQUEST_COOKIE = Pattern.compile("^Cookie: (.*)$",  Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
    private final static Pattern RESPONSE_COOKIE = Pattern.compile("^Set-Cookie: (.*)$", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    /**
     * https://www.owasp.org/index.php/SCG_D_BIGIP
     * https://support.f5.com/csp/article/K6917
     *
     * BIGipServer<pool_name>=1677787402.36895.0000
     * BIGipServer<pool_name>=vi20010112000000000000000000000030.20480
     * BIGipServer<pool_name>=rd5o00000000000000000000ffffc0000201o80
     * BIGipServer<pool_name>=rd3o20010112000000000000000000000030o80
     *
     */
    private final static String IPv4_PREFIX = "00000000000000000000ffff";
    private final static Pattern BIGIP_COOKIE = Pattern.compile("(BIGipServer[^\\s=]*?|[^\\s=]*?)=([0-9A-Za-z.]+)", Pattern.CASE_INSENSITIVE);
    private final static Pattern BIGIP_STANDARD = Pattern.compile("(\\d+)\\.(\\d+)\\.0000");
    private final static Pattern BIGIP_STANDARD_VI = Pattern.compile("vi([0-9A-Fa-f]+)\\.(\\d+)");
    private final static Pattern BIGIP_STANDARD_RD = Pattern.compile("rd\\d+o([0-9A-Fa-f]+)o(\\d+)");

    public static List<BigIPIssueItem> parseHeader(boolean messageIsRequest, byte[] messageByte) {
        List<BigIPIssueItem> list = new ArrayList<>();
        String message = StringUtil.getStringRaw(messageByte);

        if (messageIsRequest) {
            // Cookieの取得
            Matcher m = REQUEST_COOKIE.matcher(message);
            while (m.find()) {
                int cookieOffset = m.start(1);
                String cookieAll = m.group(1);
                list.addAll(parseDecryptList(messageIsRequest, cookieAll, cookieOffset));
            }
        } else {
            // Set-Cookieの取得
            Matcher m = RESPONSE_COOKIE.matcher(message);
            while (m.find()) {
                int cookieOffset = m.start(1);
                String cookieAll = m.group(1);
                list.addAll(parseDecryptList(messageIsRequest, cookieAll, cookieOffset));
            }
        }
        return list;
    }

    protected static List<BigIPIssueItem> parseDecryptList(boolean messageIsRequest, String cookieAll, int cookieOffset) {
        List<BigIPIssueItem> list = new ArrayList<>();
        if (cookieAll != null) {
            Matcher m = BIGIP_COOKIE.matcher(cookieAll);
            while (m.find()) {
                BigIPIssueItem cookieIP = new BigIPIssueItem();
                String cookieName = m.group(1);
                String cookieValue = m.group(2);
                String ip_addr = decrypt(cookieValue);
                if (ip_addr != null) {
                    cookieIP.setMessageIsRequest(messageIsRequest);
                    cookieIP.setStartsBIGipServer(cookieName.startsWith("BIGipServer"));
                    cookieIP.setIPAddr(ip_addr);
                    cookieIP.setCaptureValue(m.group(0));
                    cookieIP.setEncryptCookie(cookieValue);
                    cookieIP.setStart(cookieOffset + m.start());
                    cookieIP.setEnd(cookieOffset + m.end());
                    if (cookieIP.isPrivateIP()) {
                        cookieIP.setServerity(Severity.LOW);
                        cookieIP.setConfidence(Confidence.CERTAIN);
                    } else if (cookieIP.isLinkLocalIP()) {
                        cookieIP.setServerity(Severity.LOW);
                        cookieIP.setConfidence(Confidence.CERTAIN);
                    } else {
                        cookieIP.setServerity(Severity.INFORMATION);
                        cookieIP.setConfidence(Confidence.FIRM);
                    }
                    list.add(cookieIP);
                }
            }
        }
        return list;
    }

    /*
     * https://support.f5.com/csp/article/K6917
    **/
    public static String decrypt(String value) {
        String ipaddr = null;
        if (ipaddr == null) {
            Matcher m1 = BIGIP_STANDARD.matcher(value);
            if (m1.find()) {
                String enc_ip = m1.group(1);
                String enc_port = m1.group(2);
                String ip_addr = IpUtil.decimalToIPv4(Long.parseLong(enc_ip), ByteOrder.LITTLE_ENDIAN);
                int ip_port = IpUtil.decimalToPort(Integer.parseInt(enc_port), ByteOrder.LITTLE_ENDIAN);
                if (IpUtil.isIPv4Valid(ip_addr, ip_port)) {
                    ipaddr = String.format("%s:%d", ip_addr, ip_port);
                }
            }
        }
        if (ipaddr == null) {
            Matcher m1 = BIGIP_STANDARD_VI.matcher(value);
            if (m1.find()) {
                String enc_ip = m1.group(1);
                String enc_port = m1.group(2);
                String ip_addr = IpUtil.hexToIPv6(enc_ip);
                int ip_port = IpUtil.decimalToPort(Integer.parseInt(enc_port), ByteOrder.LITTLE_ENDIAN);
                if (IpUtil.isIPv6Valid(ip_addr, ip_port)) {
                    ipaddr = String.format("%s:%d", ip_addr, ip_port);
                }
            }
        }
        if (ipaddr == null) {
            Matcher m1 = BIGIP_STANDARD_RD.matcher(value);
            if (m1.find()) {
                String enc_ip = m1.group(1);
                String enc_port = m1.group(2);
                // ::ffff
                if (enc_ip.startsWith(IPv4_PREFIX)) {
                    String ip_addr = IpUtil.hexToIPv4(enc_ip.substring(IPv4_PREFIX.length()), ByteOrder.BIG_ENDIAN);
                    int ip_port = IpUtil.decimalToPort(Integer.parseInt(enc_port), ByteOrder.BIG_ENDIAN);
                    if (IpUtil.isIPv4Valid(ip_addr, ip_port)) {
                        ipaddr = String.format("%s:%d", ip_addr, ip_port);
                    }
                } else {
                    String ip_addr = IpUtil.hexToIPv6(enc_ip);
                    int ip_port = IpUtil.decimalToPort(Integer.parseInt(enc_port), ByteOrder.BIG_ENDIAN);
                    if (IpUtil.isIPv6Valid(ip_addr, ip_port)) {
                        ipaddr = String.format("%s:%d", IpUtil.hexToIPv6(enc_ip), ip_port);
                    }
                }
            }
        }
        return ipaddr;
    }

    public void freePassiveScan(IHttpRequestResponse messageInfo) {
        List<BigIPIssueItem> bigIpList = new ArrayList<>();
        // Response判定
        if (property.getScanResponse() && messageInfo.getResponse() != null) {
            bigIpList.addAll(this.parseMessage(false, messageInfo.getResponse()));
        }
        // Request判定
        if (property.getScanRequest() && messageInfo.getRequest() != null) {
            bigIpList.addAll(this.parseMessage(true, messageInfo.getRequest()));
        }
        StringBuilder buff = new StringBuilder();
        for (int i = 0; i < bigIpList.size(); i++) {
            BigIPIssueItem item = bigIpList.get(i);
            //System.out.println("bigip:" + bigIpList[i].getEncryptCookie() + "=" + bigIpList[i].getIPAddr());
            // Private IP Only にチェックがついていてPrivate IPで無い場合はスキップ
            if (property.isDetectionPrivateIP() && !(item.isPrivateIP() || item.isLinkLocalIP())) {
                continue;
            }
            if (buff.length() == 0) {
                buff.append("BigIP:");
            } else {
                buff.append(", ");
            }
            buff.append(item.getIPAddr());
        }
        if (buff.length() > 0) {
            if (property.getNotifyTypes().contains(NotifyType.ITEM_HIGHLIGHT)) {
                messageInfo.setHighlight(property.getHighlightColor().toString());
            }
            if (property.getNotifyTypes().contains(NotifyType.COMMENT)) {
                messageInfo.setComment(buff.toString());
            }
        }
    }

    private final BigIPCookieProperty property = new BigIPCookieProperty();

    @Override
    public String getTabCaption() {
        return "BIG-IP Cookie";
    }

    @Override
    public Component getUiComponent() {
        return this.tabBigIPCookie;
    }

    @Override
    public String getSettingName() {
        return SIGNATURE_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        BigIPCookieProperty bigIPCookieProperty = JsonUtil.jsonFromString(value, BigIPCookieProperty.class, true);

        this.property.setProperty(bigIPCookieProperty);
        this.tabBigIPCookie.setProperty(this.property);
    }

    @Override
    public String loadSetting() {
        BigIPCookieProperty bigIPCookieProperty = this.tabBigIPCookie.getProperty();
        this.property.setProperty(bigIPCookieProperty);
        return JsonUtil.jsonToString(this.property, true);
    }

    @Override
    public String defaultSetting() {
        BigIPCookieProperty bigIPCookieProperty = new BigIPCookieProperty();
        return JsonUtil.jsonToString(bigIPCookieProperty, true);
    }

}
