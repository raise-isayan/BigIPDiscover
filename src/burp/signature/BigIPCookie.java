/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.signature;

import burp.BigIpDecrypt;
import burp.BurpExtender;
import static burp.BurpExtenderImpl.getCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.OptionProperty;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author isayan
 */
public class BigIPCookie implements Signature<BigIpDecrypt> {

    private final OptionProperty option;
    
    public BigIPCookie(final OptionProperty option) {
        this.option = option;
    }

    @Override
    public IScannerCheck passiveScanCheck() {
        return new IScannerCheck() {
            @Override
            public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
                List<IScanIssue> issue = null;
                List<BigIpDecrypt> bigIpList = null;
                // Response判定
                if (issue == null && option.getScan().getScanResponse() && baseRequestResponse.getResponse() != null) {
                    // ヘッダのみ抽出（逆に遅くなってるかも？）
                    IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(baseRequestResponse.getResponse());
                    byte resHeader[] = Arrays.copyOfRange(baseRequestResponse.getResponse(), 0, resInfo.getBodyOffset());
                    bigIpList = BigIpDecrypt.parseMessage(false, resHeader);
                    issue = makeIssueList(false, baseRequestResponse, bigIpList);
                }
                // Request判定
                if (issue == null && option.getScan().getScanRequest() && baseRequestResponse.getRequest() != null) {
                    // ヘッダのみ抽出（逆に遅くなってるかも？）
                    IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(baseRequestResponse.getRequest());
                    byte reqHeader[] = Arrays.copyOfRange(baseRequestResponse.getRequest(), 0, reqInfo.getBodyOffset());
                    bigIpList = BigIpDecrypt.parseMessage(true, reqHeader);
                    issue = makeIssueList(true, baseRequestResponse, bigIpList);
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
                    messageInfoMark = getCallbacks().applyMarkers(baseRequestResponse, requestResponseMarkers, null);
                } else {
                    messageInfoMark = getCallbacks().applyMarkers(baseRequestResponse, null, requestResponseMarkers);
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
                IRequestInfo reqInfo = getCallbacks().getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
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
                String severity = "Information";
                for (BigIpDecrypt markIP : markIPList) {
                    if (markIP.isPrivateIP()) {
                        severity = "Low";
                        break; // ひとつでもPrivateIPがあればリスクをLowに
                    }
                }
                return severity;
            }

            @Override
            public String getConfidence() {
                return "Certain";
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
    
}
