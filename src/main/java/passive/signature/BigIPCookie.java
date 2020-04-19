package passive.signature;

import passive.SignatureItem;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import extend.util.IpUtil;
import extend.util.Util;
import extend.view.base.MatchItem;
import java.net.URL;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import passive.IssueItem;
import passive.PassiveCheckAdapter;

/**
 *
 * @author isayan
 */
public class BigIPCookie extends SignatureItem<BigIPIssueItem> {

    private final BigIPCookieProperty property;

    public BigIPCookie(final BigIPCookieProperty property) {
        super("BIG-IP Cookie Discloses IP Address", MatchItem.Severity.LOW);
        this.property = property;
    }

    @Override
    public IScannerCheck passiveScanCheck() {
        return new PassiveCheckAdapter() {
            @Override
            public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
                List<IScanIssue> issue = null;
                // Response判定
                if (property.getScanResponse() && baseRequestResponse.getResponse() != null) {
                    issue = makeIssueList(false, baseRequestResponse, getBigIPList(false, baseRequestResponse.getResponse()));
                }
                // Request判定
                if (issue == null && property.getScanRequest() && baseRequestResponse.getRequest() != null) {
                    issue = makeIssueList(true, baseRequestResponse, getBigIPList(true, baseRequestResponse.getRequest()));
                }

                return issue;
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
                if (markList.size() > 0) {
                    List<IScanIssue> issues = new ArrayList<>();
                    IHttpRequestResponseWithMarkers applyMarks = applyMarkers(baseRequestResponse, markList);
                    issues.add(makeScanIssue(applyMarks, markList));
                    return issues;
                } else {
                    return null;
                }
            }

        };
    }

    @Override
    public IScanIssue makeScanIssue(IHttpRequestResponse messageInfo, List<BigIPIssueItem> issueItem) {

        return new IScanIssue() {

            public BigIPIssueItem getItem() {
                if (issueItem.size() > 0) {
                    return issueItem.get(0);
                } else {
                    return null;
                }
            }

            @Override
            public URL getUrl() {
                IRequestInfo reqInfo = BurpExtender.getCallbacks().getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                return reqInfo.getUrl();
            }

            @Override
            public String getIssueName() {
                return BigIPCookie.this.getIssueName();
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
                        + "<h4>Reference:</h4>"
                        + "<ul>"
                        + "  <li><a href=\"https://www.owasp.org/index.php/SCG_D_BIGIP\">https://www.owasp.org/index.php/SCG_D_BIGIP</a></li>"
                        + "  <li><a href=\"https://support.f5.com/csp/article/K6917\">https://support.f5.com/csp/article/K6917</a></li>"
                        + "</ul>"
                        + "<h4>Examples:</h4>"
                        + "<ul>"
                        + "  <li>BIGipServer<pool_name>=1677787402.36895.0000</li>"
                        + "  <li>BIGipServer<pool_name>=vi20010112000000000000000000000030.20480</li>"
                        + "  <li>BIGipServer<pool_name>=rd5o00000000000000000000ffffc0000201o80</li>"
                        + "  <li>BIGipServer<pool_name>=rd3o20010112000000000000000000000030o80</li>"
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

    public List<BigIPIssueItem> getBigIPList(boolean messageIsRequest, byte[] message) {
        List<BigIPIssueItem> cookieIPList = new ArrayList<>();
        // Response判定
        if (!messageIsRequest) {
            // ヘッダのみ抽出（逆に遅くなってるかも？）
            IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(message);
            byte resHeader[] = Arrays.copyOfRange(message, 0, resInfo.getBodyOffset());
            cookieIPList.addAll(parseMessage(false, resHeader));
        }
        // Request判定
        if (messageIsRequest && message != null) {
            // ヘッダのみ抽出（逆に遅くなってるかも？）
            IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(message);
            byte reqHeader[] = Arrays.copyOfRange(message, 0, reqInfo.getBodyOffset());
            cookieIPList.addAll(parseMessage(true, reqHeader));
        }
        return cookieIPList;
    }

    private final static Pattern REQUEST_COOKE = Pattern.compile("^Cookie: (.*)$", Pattern.MULTILINE);
    private final static Pattern RESPONSE_COOKE = Pattern.compile("^Set-Cookie: (.*)$", Pattern.MULTILINE);

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
    private final static Pattern BIGIP_COOKIE = Pattern.compile("(BIGipServer[^\\s=]*?|[^\\s=]*?)=([0-9a-z.]+)");
    private final static Pattern BIGIP_STANDARD = Pattern.compile("(\\d+)\\.(\\d+)\\.0000");
    private final static Pattern BIGIP_STANDARD_VI = Pattern.compile("vi(\\d+)\\.(\\d+)");
    private final static Pattern BIGIP_STANDARD_RD = Pattern.compile("rd\\d+o([0-9a-z]+)o(\\d+)");

    public static List<BigIPIssueItem> parseMessage(boolean messageIsRequest, byte[] messageByte) {
        List<BigIPIssueItem> list = new ArrayList<>();
        String message = Util.getRawStr(messageByte);
        String cookieAll = null;
        int cookieOffset = 0;

        if (messageIsRequest) {
            // Cookieの取得
            Matcher m = REQUEST_COOKE.matcher(message);
            while (m.find()) {
                cookieOffset = m.start(1);
                cookieAll = m.group(1);
                list.addAll(parseDecryptList(messageIsRequest, cookieAll, cookieOffset));
            }
        } else {
            // Set-Cookieの取得
            Matcher m = RESPONSE_COOKE.matcher(message);
            while (m.find()) {
                cookieOffset = m.start(1);
                cookieAll = m.group(1);
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
                        cookieIP.setServerity(MatchItem.Severity.LOW);
                        cookieIP.setConfidence(MatchItem.Confidence.CERTAIN);
                    } else if (cookieIP.isLinkLocalIP()) {
                        cookieIP.setServerity(MatchItem.Severity.LOW);
                        cookieIP.setConfidence(MatchItem.Confidence.CERTAIN);
                    } else {
                        cookieIP.setServerity(MatchItem.Severity.INFORMATION);
                        cookieIP.setConfidence(MatchItem.Confidence.FIRM);
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
                ipaddr = String.format("%s:%d", IpUtil.decimalToIPv4(Long.parseLong(enc_ip), ByteOrder.LITTLE_ENDIAN), IpUtil.decimalToPort(Integer.parseInt(enc_port), ByteOrder.LITTLE_ENDIAN));
            }
        }
        if (ipaddr == null) {
            Matcher m1 = BIGIP_STANDARD_VI.matcher(value);
            if (m1.find()) {
                String enc_ip = m1.group(1);
                String enc_port = m1.group(2);
                ipaddr = String.format("%s:%d", IpUtil.hexToIPv6(enc_ip), IpUtil.decimalToPort(Integer.parseInt(enc_port), ByteOrder.LITTLE_ENDIAN));
            }
        }
        if (ipaddr == null) {
            Matcher m1 = BIGIP_STANDARD_RD.matcher(value);
            if (m1.find()) {
                String enc_ip = m1.group(1);
                String enc_port = m1.group(2);
                // ::ffff
                if (enc_ip.startsWith(IPv4_PREFIX)) {
                    ipaddr = String.format("%s:%d", IpUtil.hexToIPv4(enc_ip.substring(IPv4_PREFIX.length()), ByteOrder.BIG_ENDIAN), IpUtil.decimalToPort(Integer.parseInt(enc_port), ByteOrder.BIG_ENDIAN));
                } else {
                    ipaddr = String.format("%s:%d", IpUtil.hexToIPv6(enc_ip), IpUtil.decimalToPort(Integer.parseInt(enc_port), ByteOrder.BIG_ENDIAN));
                }
            }
        }
        return ipaddr;
    }

}
