package passive.signature;

import burp.BigIpDecrypt;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.IOptionProperty;
import extend.view.base.MatchItem;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author isayan
 */
public class BigIPCookie implements Signature<List<BigIpDecrypt>> {

    private final IOptionProperty option;

    public BigIPCookie(final IOptionProperty option) {
        this.option = option;
    }

    @Override
    public IScannerCheck passiveScanCheck() {
        return new IScannerCheck() {
            @Override
            public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
                List<IScanIssue> issue = null;
                // Response判定
                if (option.getScan().getScanResponse() && baseRequestResponse.getResponse() != null) {
                    issue = makeIssueList(false, baseRequestResponse, getBigIPList(false, baseRequestResponse.getResponse()));                    
                }
                // Request判定
                if (option.getScan().getScanRequest() && baseRequestResponse.getRequest() != null) {
                    issue = makeIssueList(true, baseRequestResponse, getBigIPList(true, baseRequestResponse.getRequest()));                    
                }

                return issue;
            }
            
            public List<IScanIssue> makeIssueList(boolean messageIsRequest, IHttpRequestResponse baseRequestResponse, List<BigIpDecrypt> bigIpList) {
                List<BigIpDecrypt> markIPList = new ArrayList<>();
                List<int[]> requestResponseMarkers = new ArrayList<>();
                for (int i = 0; i < bigIpList.size(); i++) {
                    BigIpDecrypt item = bigIpList.get(i);
                    // Private IP Only にチェックがついていてPrivate IPで無い場合はスキップ
                    if (option.getScan().isDetectionPrivateIP() && !item.isPrivateIP()) {
                        continue;
                    }
                    markIPList.add(item);
                    requestResponseMarkers.add(new int[]{item.start(), item.end()});
                }
                IHttpRequestResponseWithMarkers messageInfoMark = null;
                if (messageIsRequest) {
                    messageInfoMark = BurpExtender.getCallbacks().applyMarkers(baseRequestResponse, requestResponseMarkers, null);
                } else {
                    messageInfoMark = BurpExtender.getCallbacks().applyMarkers(baseRequestResponse, null, requestResponseMarkers);
                }

                if (markIPList.size() > 0) {
                    List<IScanIssue> issues = new ArrayList<>();
                    issues.add(makeScanIssue(messageInfoMark, markIPList));
                    return issues;
                } else {
                    return null;
                }
            }

            @Override
            public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
                return null;
            }

            @Override
            public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
                if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
                    // 同一とみなせる場合は報告をスキップ                    
                    return -1;
                }
                return 0;
            }

        };
    }

    @Override
    public IScanIssue makeScanIssue(IHttpRequestResponse messageInfo, List<BigIpDecrypt> markIPList) {

        return new IScanIssue() {
            @Override
            public URL getUrl() {
                IRequestInfo reqInfo = BurpExtender.getCallbacks().getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                return reqInfo.getUrl();
            }

            @Override
            public String getIssueName() {
                return "Insecure BigIP Cookie";
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
                MatchItem.Severity severity = MatchItem.Severity.INFORMATION;
                for (BigIpDecrypt markIP : markIPList) {
                    if (markIP.isPrivateIP()) {
                        severity = MatchItem.Severity.LOW;
                        break; // ひとつでもPrivateIPがあればリスクをLowに
                    }
                }
                return severity.toString();
            }

            @Override
            public String getConfidence() {
                MatchItem.Confidence confidence = MatchItem.Confidence.CERTAIN;
                return confidence.toString();
            }

            @Override
            public String getIssueBackground() {
                final String ISSUE_BACKGROUND = "\r\n"
                        + "<h4>Reference:</h4>"
                        + "<ul>"
                        + "  <li><a href=\"https://www.owasp.org/index.php/SCG_D_BIGIP\">https://www.owasp.org/index.php/SCG_D_BIGIP</a></li>"
                        + "  <li><a href=\"https://support.f5.com/csp/article/K6917\">https://support.f5.com/csp/article/K6917</a></li>"
                        + "<ul>"
                        + "<h4>Examples:</h4>"
                        + "<ul>"
                        + "  <li>BIGipServer<pool_name>=1677787402.36895.0000</li>"
                        + "  <li>BIGipServer<pool_name>=vi20010112000000000000000000000030.20480</li>"
                        + "  <li>BIGipServer<pool_name>=rd5o00000000000000000000ffffc0000201o80</li>"
                        + "  <li>BIGipServer<pool_name>=rd3o20010112000000000000000000000030o80</li>"
                        + "<ul>";
                return ISSUE_BACKGROUND;
            }

            @Override
            public String getRemediationBackground() {
                return null;
            }

            @Override
            public String getIssueDetail() {
                StringBuilder buff = new StringBuilder();
                buff.append("<h4>Datail:</h4>");
                for (BigIpDecrypt markIP : markIPList) {
                    String cookieType = markIP.messageIsRequest() ? "Cookie" : "Set-Cookie";
                    buff.append("<div>");
                    buff.append("<ul>");
                    buff.append("<li>");
                    buff.append(String.format("%s: %s", cookieType, markIP.getSelectionCookie()));
                    buff.append("</li>");
                    buff.append("<li>");
                    buff.append(String.format("ip address:%s", markIP.getIPAddr()));
                    buff.append("</li>");
                    buff.append("<li>");
                    buff.append(String.format("private ip:%s", markIP.isPrivateIP()));
                    buff.append("</li>");
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

    public List<BigIpDecrypt> getBigIPList(boolean messageIsRequest, byte [] message) {
        List<BigIpDecrypt> bigIpList = new ArrayList<>();
        // Response判定
        if (!messageIsRequest) {
            // ヘッダのみ抽出（逆に遅くなってるかも？）
            IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(message);
            byte resHeader[] = Arrays.copyOfRange(message, 0, resInfo.getBodyOffset());
            bigIpList.addAll(BigIpDecrypt.parseMessage(false, resHeader));
        }
        // Request判定
        if (messageIsRequest && message != null) {
            // ヘッダのみ抽出（逆に遅くなってるかも？）
            IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(message);
            byte reqHeader[] = Arrays.copyOfRange(message, 0, reqInfo.getBodyOffset());
            bigIpList.addAll(BigIpDecrypt.parseMessage(true, reqHeader));
        }
        return bigIpList;                      
    }
    
}
