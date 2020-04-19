package passive.signature;

import passive.SignatureItem;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import extend.util.Util;
import extend.view.base.MatchItem;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import passive.IssueItem;
import passive.PassiveCheckAdapter;

/**
 *
 * @author isayan
 */
public class IPAddressDisclosed extends SignatureItem<IPAddressIssueItem> {

    public IPAddressDisclosed() {
        super("Private IP addresses disclosed(Link local)", MatchItem.Severity.LOW);
    }

    @Override
    public IScannerCheck passiveScanCheck() {
        return new PassiveCheckAdapter() {
            @Override
            public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
                List<IScanIssue> issue = null;
                // Response判定
                if (baseRequestResponse.getResponse() != null) {
                    issue = makeIssueList(false, baseRequestResponse, parseMessage(false, baseRequestResponse.getResponse()));
                }
                return issue;
            }

            public List<IScanIssue> makeIssueList(boolean messageIsRequest, IHttpRequestResponse baseRequestResponse, List<IPAddressIssueItem> issueList) {
                List<IPAddressIssueItem> markList = new ArrayList<>();
                for (int i = 0; i < issueList.size(); i++) {
                    IPAddressIssueItem item = issueList.get(i);
                    // Link Local IPで無い場合はスキップ
                    if (!(item.isLinkLocalIP())) {
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
    public IScanIssue makeScanIssue(IHttpRequestResponse messageInfo, List<IPAddressIssueItem> issueItem) {

        return new IScanIssue() {

            public IPAddressIssueItem getItem() {
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
                return IPAddressDisclosed.this.getIssueName();
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
                        + "  <li><a href=\"https://tools.ietf.org/html/rfc3927\">https://tools.ietf.org/html/rfc3927</a></li>"
                        + "</ul>"
                        + "<h4>Examples:</h4>"
                        + "<ul>"
                        + "  <li>ipv4:169.254.0.0/16</li>"
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
                for (IPAddressIssueItem markIP : issueItem) {
                    buff.append("<div>");
                    buff.append("<ul>");
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

    private final static String IPv4_PREFIX = "00000000000000000000ffff";
    private final static Pattern IPv4_ADDR = Pattern.compile("(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})");        
    private final static Pattern IPv6_ADDR = Pattern.compile(
        "([0-9a-f]{1,4}(:[0-9a-f]{1,4}){7})|::"
      + "|:(:[0-9a-f]{1,4}){1,7}|([0-9a-f]{1,4}:){1,7}:"
      + "|([0-9a-f]{1,4}:){1}(:[0-9a-f]{1,4}){1,6}|([0-9a-f]{1,4}:){2}(:[0-9a-f]{1,4}){1,5}"
      + "|([0-9a-f]{1,4}:){3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){4}(:[0-9a-f]{1,4}){1,3}"
      + "|([0-9a-f]{1,4}:){5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}){1}"
    );        
    
    public static List<IPAddressIssueItem> parseMessage(boolean messageIsRequest, byte[] messageByte) {
        List<IPAddressIssueItem> list = new ArrayList<>();
        String message = Util.getRawStr(messageByte);
        String ipAddressAll = null;
        int ipAddressOffset = 0;

        if (!messageIsRequest) {
            // IP Addressの取得
            Matcher m = IPv4_ADDR.matcher(message);
            while (m.find()) {
                ipAddressOffset = m.start(1);
                ipAddressAll = m.group(1);
                list.addAll(parseIPAddrssList(messageIsRequest, ipAddressAll, ipAddressOffset));
            }
        }
        return list;
    }

    protected static List<IPAddressIssueItem> parseIPAddrssList(boolean messageIsRequest, String ipAddressAll, int ipAddressOffset) {
        List<IPAddressIssueItem> list = new ArrayList<>();
        if (ipAddressAll != null) {
            Matcher m = IPv4_ADDR.matcher(ipAddressAll);
            while (m.find()) {
                IPAddressIssueItem ipItem = new IPAddressIssueItem();
                String ipAddr = m.group(1);
                if (ipAddr != null) {
                    ipItem.setMessageIsRequest(messageIsRequest);
                    ipItem.setIPAddr(ipAddr);
                    ipItem.setCaptureValue(m.group(1));
                    ipItem.setStart(ipAddressOffset + m.start());
                    ipItem.setEnd(ipAddressOffset + m.end());
                    if (ipItem.isPrivateIP()) {
                        ipItem.setServerity(MatchItem.Severity.LOW);
                        ipItem.setConfidence(MatchItem.Confidence.CERTAIN);
                    } else if (ipItem.isLinkLocalIP()) {
                        ipItem.setServerity(MatchItem.Severity.LOW);
                        ipItem.setConfidence(MatchItem.Confidence.CERTAIN);
                    } else {
                        ipItem.setServerity(MatchItem.Severity.INFORMATION);
                        ipItem.setConfidence(MatchItem.Confidence.FIRM);
                    }
                    list.add(ipItem);
                }
            }
        }
        return list;
    }


}
