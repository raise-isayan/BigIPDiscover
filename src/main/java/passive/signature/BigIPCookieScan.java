package passive.signature;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import extension.burp.Confidence;
import extension.burp.IBurpTab;
import extension.burp.IPropertyConfig;
import extension.burp.Severity;
import extension.burp.scanner.IssueItem;
import extension.burp.scanner.ScannerCheckAdapter;
import extension.burp.scanner.SignatureScanBase;
import extension.helpers.HttpRequestWapper;
import extension.helpers.HttpResponseWapper;
import extension.helpers.HttpUtil;
import extension.helpers.IpUtil;
import extension.helpers.json.JsonUtil;
import java.awt.Component;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class BigIPCookieScan extends SignatureScanBase<BigIPIssueItem> implements IBurpTab, IPropertyConfig {

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
    public ScanCheck passiveScanCheck() {
        return new ScannerCheckAdapter() {
            @Override
            public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
                List<AuditIssue> issues = new ArrayList<>();
                // Response判定
                HttpResponseWapper wrapResponse = new HttpResponseWapper(baseRequestResponse.response());
                if (property.getScanResponse() && wrapResponse.hasHttpResponse()) {
                    issues.addAll(makeIssueList(false, baseRequestResponse, parseMessage(false, baseRequestResponse)));
                }
                // Request判定
                HttpRequestWapper wrapRequest = new HttpRequestWapper(baseRequestResponse.request());
                if (issues.isEmpty() && property.getScanRequest() && wrapRequest.hasHttpRequest()) {
                    issues.addAll(makeIssueList(true, baseRequestResponse, parseMessage(true, baseRequestResponse)));
                }
                return AuditResult.auditResult(issues);
            }
        };
    }

    public List<AuditIssue> makeIssueList(boolean messageIsRequest, HttpRequestResponse baseRequestResponse, List<BigIPIssueItem> markIssueList) {
        List<BigIPIssueItem> markList = new ArrayList<>();
        for (int i = 0; i < markIssueList.size(); i++) {
            BigIPIssueItem item = markIssueList.get(i);
            // Private IP Only にチェックがついていてPrivate IPで無い場合はスキップ
            if (property.isDetectionPrivateIP() && !(item.isPrivateIP() || item.isLinkLocalIP())) {
                continue;
            }
            markList.add(item);
        }
        List<AuditIssue> issues = new ArrayList<>();
        if (!markList.isEmpty()) {
            HttpRequestResponse applyMarks = applyMarkers(baseRequestResponse, markList);
            issues.add(makeScanIssue(applyMarks, markList));
        }
        return issues;
    }

    public AuditIssue makeScanIssue(HttpRequestResponse messageInfo, List<BigIPIssueItem> issueItems) {

        return new AuditIssue() {

            public BigIPIssueItem getItem() {
                if (issueItems.isEmpty()) {
                    return null;
                } else {
                    return issueItems.get(0);
                }
            }

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

            @Override
            public String name() {
                return BigIPCookieScan.this.getIssueName();
            }

            @Override
            public String detail() {
                StringBuilder buff = new StringBuilder();
                buff.append("<h4>IP Address:</h4>");
                for (BigIPIssueItem markIP : issueItems) {
                    String cookieType = markIP.isMessageIsRequest() ? "Cookie" : "Set-Cookie";
                    buff.append("<div>");
                    buff.append("<ul>");
                    buff.append("<li>");
                    buff.append(String.format("%s: %s", cookieType, HttpUtil.toHtmlEncode(markIP.getCaptureValue())));
                    buff.append("</li>");
                    buff.append("<li>");
                    buff.append(String.format("ip address: %s", HttpUtil.toHtmlEncode(markIP.getIPAddr())));
                    buff.append("</li>");
                    if (markIP.isLinkLocalIP()) {
                        buff.append("<li>");
                        buff.append(String.format("Link local IP: %s", markIP.isLinkLocalIP()));
                        buff.append("</li>");
                    } else {
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
            public String remediation() {
                return null;
            }

            @Override
            public HttpService httpService() {
                return messageInfo.request().httpService();
            }

            @Override
            public String baseUrl() {
                return messageInfo.request().url();
            }

            @Override
            public AuditIssueSeverity severity() {
                IssueItem item = getItem();
                return item.getServerity().toAuditIssueSeverity();
            }

            @Override
            public AuditIssueConfidence confidence() {
                IssueItem item = getItem();
                return item.getConfidence().toAuditIssueConfidence();
            }

            @Override
            public List<HttpRequestResponse> requestResponses() {
                return Arrays.asList(messageInfo);
            }

            @Override
            public AuditIssueDefinition definition() {
                return AuditIssueDefinition.auditIssueDefinition(name(), ISSUE_BACKGROUND, remediation(), severity());
            }

            @Override
            public List<Interaction> collaboratorInteractions() {
                return new ArrayList<>();
            }
        };

    }

    public static List<BigIPIssueItem> parseMessage(boolean messageIsRequest, HttpRequestResponse baseRequestResponse) {
        List<BigIPIssueItem> cookieIPList = new ArrayList<>();
        // Response判定
        if (!messageIsRequest) {
            HttpResponseWapper wrapResponse = new HttpResponseWapper(baseRequestResponse.response());
            cookieIPList.addAll(parseHeader(false, wrapResponse.getHeader()));
        }
        // Request判定
        if (messageIsRequest) {
            HttpRequestWapper wrapRequest = new HttpRequestWapper(baseRequestResponse.request());
            cookieIPList.addAll(parseHeader(true, wrapRequest.getHeader()));
        }
        return cookieIPList;
    }

    private final static Pattern REQUEST_COOKIE = Pattern.compile("^Cookie: (.*)$", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
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

    public static List<BigIPIssueItem> parseHeader(boolean messageIsRequest, String message) {
        List<BigIPIssueItem> list = new ArrayList<>();

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
