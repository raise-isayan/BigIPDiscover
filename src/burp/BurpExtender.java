/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import static burp.BurpExtenderImpl.getCallbacks;
import extend.util.BurpWrap;
import extend.util.ConvertUtil;
import extend.view.base.MatchItem;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl implements IBurpExtender, IHttpListener, OptionProperty {
    private final BigIpDecryptTab tabbetOption = new BigIpDecryptTab();
    private boolean burpProfessional = false;
   
    public static BurpExtender getInstance() {
        return BurpExtenderImpl.<BurpExtender>getInstance();
    }
    
    public boolean isProfessional() {
        return burpProfessional;
    }
    
    @Override
    /* IBurpExtender interface implements method */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        super.registerExtenderCallbacks(callbacks);
        BurpWrap.Version version = new BurpWrap.Version(callbacks);
        callbacks.addSuiteTab(this.tabbetOption);
        this.burpProfessional = version.isProfessional();
        try {
            String configXML = getCallbacks().loadExtensionSetting("configXML");
            if (configXML != null) {
                Config.loadFromXml(ConvertUtil.decompressZlibBase64(configXML), this.getProperty());                
            }
        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        this.tabbetOption.setScanProperty(this.getScan());
        this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());
                 
        // プロフェッショナル版の場合
        if (this.burpProfessional) {
            callbacks.registerScannerCheck(professionalPassiveScanCheck());
        } // フリー版の場合
        else {
            callbacks.registerHttpListener(this);
        }

    }
    
    // プロフェッショナル版の実装
    public IScannerCheck professionalPassiveScanCheck() {
        return new IScannerCheck() {
            @Override
            public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
                List<IScanIssue> issue = null;
                BigIpDecrypt [] bigIpList = new BigIpDecrypt[0];
                // Response判定
                if (issue == null && getScan().getScanResponse() && baseRequestResponse.getResponse() != null) {
                    // ヘッダのみ抽出（逆に遅くなってるかも？）
                    IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(baseRequestResponse.getResponse());
                    byte resHeader [] = Arrays.copyOfRange(baseRequestResponse.getResponse(), 0, resInfo.getBodyOffset());
                    bigIpList = BigIpDecrypt.parseDecrypts(false, resHeader);
                    issue = makeIssueList(false, baseRequestResponse, bigIpList);
                }
                // Request判定
                if (issue == null && getScan().getScanRequest() && baseRequestResponse.getRequest() != null) {
                    // ヘッダのみ抽出（逆に遅くなってるかも？）
                    IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(baseRequestResponse.getRequest());
                    byte reqHeader [] = Arrays.copyOfRange(baseRequestResponse.getRequest(), 0, reqInfo.getBodyOffset());
                    bigIpList = BigIpDecrypt.parseDecrypts(true, reqHeader);
                    issue = makeIssueList(true, baseRequestResponse, bigIpList);
                }
                return issue;
            }

            public List<IScanIssue> makeIssueList(boolean messageIsRequest, IHttpRequestResponse baseRequestResponse, BigIpDecrypt [] bigIpList) {
                List<BigIpDecrypt> markIPList = new ArrayList<>();                
                List<int []> requestResponseMarkers = new ArrayList<>();                
                for (int i = 0; i < bigIpList.length; i++) {
                    // Private IP Only にチェックがついていてPrivate IPで無い場合はスキップ
                    if (getScan().isDetectionPrivateIP() && !bigIpList[i].isPrivateIP()) {
                        continue;
                    }
                    markIPList.add(bigIpList[i]);
                    requestResponseMarkers.add(new int[]{ bigIpList[i].start(), bigIpList[i].end()});                    
                }
                IHttpRequestResponseWithMarkers messageInfoMark = null;
                if (messageIsRequest) {
                    messageInfoMark = getCallbacks().applyMarkers(baseRequestResponse, requestResponseMarkers, null);            
                } else {
                    messageInfoMark = getCallbacks().applyMarkers(baseRequestResponse, null, requestResponseMarkers);            
                }

                if (markIPList.size() > 0) {
                    List<IScanIssue> issues = new ArrayList<>();
                    issues.add(makeIssue(markIPList, messageInfoMark));
                    return issues;                
                }
                else {
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

    public IScanIssue makeIssue(final List<BigIpDecrypt> markIPList, final IHttpRequestResponse messageInfo) {

        return new IScanIssue() {
            @Override
            public URL getUrl() {
                IRequestInfo reqInfo = getCallbacks().getHelpers().analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                return reqInfo.getUrl();
            }

            @Override
            public String getIssueName() {
                return "Persistence Cookie Information Leakage (BigIP)";
            }

            @Override
            public int getIssueType() {
                /**
                 * https://portswigger.net/knowledgebase/issues/ Extension generated issue
                 */
                return 0x08000000;
            }

            @Override
            public String getSeverity() {
                String severity = "Information";
                for (BigIpDecrypt markIP: markIPList) {
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
                final String ISSUE_BACKGROUND =  "\r\n"
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
                    + "<ul>" ;
                return ISSUE_BACKGROUND;
            }

            @Override
            public String getRemediationBackground() {
                final String REMEDIATION_BACKGROUND =  "\r\n"
                    + "<h4>Reference:</h4>"
                    + "<ul>" 
                    + "  <li><a href=\"https://www.owasp.org/index.php/SCG_D_BIGIP\">https://www.owasp.org/index.php/SCG_D_BIGIP</a></li>"
                    + "  <li><a href=\"https://support.f5.com/csp/article/K6917\">https://support.f5.com/csp/article/K6917</a></li>"
                    + "<ul>" ;
                return REMEDIATION_BACKGROUND;
            }

            @Override
            public String getIssueDetail() {
                final String ISSUE_DETAIL =  "\r\n"
                    + "<h4>Datail:</h4>"
                    + "%s";

                StringBuffer buff = new StringBuffer();
                for (BigIpDecrypt markIP : markIPList) {
                    buff.append("<h5>Cookie:</h5>");
                    buff.append("<ul>");
                    buff.append("<li>");
                    buff.append(String.format("cookie: %s", markIP.getEncryptCookie()));
                    buff.append("</li>");
                    buff.append("<li>");
                    buff.append(String.format("ip address:%s", markIP.getIPAddr()));
                    buff.append("</li>");
                    buff.append("<li>");
                    buff.append(String.format("private ip:%s", markIP.isPrivateIP()));
                    buff.append("</li>");
                    buff.append("</ul>");
                }
                return String.format(ISSUE_DETAIL, buff.toString());
            }

            @Override
            public String getRemediationDetail() {
                final String REMEDIATION_DETAIL =  "\r\n"
                    + "<h4>Reference:</h4>"
                    + "<ul>" 
                    + "  <li><a href=\"https://www.owasp.org/index.php/SCG_D_BIGIP\">https://www.owasp.org/index.php/SCG_D_BIGIP</a></li>"
                    + "  <li><a href=\"https://support.f5.com/csp/article/K6917\">https://support.f5.com/csp/article/K6917</a></li>"
                    + "<ul>" ;
                return REMEDIATION_DETAIL;
            }

            @Override
            public IHttpRequestResponse[] getHttpMessages() {
                return new IHttpRequestResponse[]{ messageInfo };
            }

            @Override
            public IHttpService getHttpService() {
                return messageInfo.getHttpService();
            }
        };
    }

    // フリー版の実装
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if ((toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) && !messageIsRequest) {
            freePassiveScan(messageInfo);
        }
    }

    public void freePassiveScan(IHttpRequestResponse messageInfo) {
        try {        
            BigIpDecrypt [] bigIpList = new BigIpDecrypt[0];
            // Response判定
            if (bigIpList.length == 0 && getScan().getScanResponse() && messageInfo.getResponse() != null) {
                // ヘッダのみ抽出（逆に遅くなってるかも？）
                IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(messageInfo.getResponse());
                byte resHeader [] = Arrays.copyOfRange(messageInfo.getResponse(), 0, resInfo.getBodyOffset());
                bigIpList = BigIpDecrypt.parseDecrypts(false, resHeader);
            }
            // Request判定
            if (bigIpList.length == 0 && getScan().getScanRequest() && messageInfo.getRequest() != null) {
                // ヘッダのみ抽出（逆に遅くなってるかも？）
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo.getRequest());
                byte reqHeader [] = Arrays.copyOfRange(messageInfo.getRequest(), 0, reqInfo.getBodyOffset());
                bigIpList = BigIpDecrypt.parseDecrypts(true, reqHeader);
            }
            StringBuilder buff = new StringBuilder();
            for (int i = 0; i < bigIpList.length; i++) {
                //System.out.println("bigip:" + bigIpList[i].getEncryptCookie() + "=" + bigIpList[i].getIPAddr());
                // Private IP Only にチェックがついていてPrivate IPで無い場合はスキップ
                if (getScan().isDetectionPrivateIP() && !bigIpList[i].isPrivateIP()) {
                    continue;
                }
                if (buff.length() == 0) {
                    buff.append("BigIP:");
                }
                else {
                    buff.append(", ");                    
                }
                buff.append(bigIpList[i].getIPAddr());                                
            }
            if (buff.length() > 0) {
                ScanProperty scan = this.getScan();
                if (scan.getNotifyTypes().contains(MatchItem.NotifyType.ITEM_HIGHLIGHT)) {
                    messageInfo.setHighlight(scan.getHighlightColor().toString());                
                }
                if (this.getScan().getNotifyTypes().contains(MatchItem.NotifyType.COMMENT)) {
                    messageInfo.setComment(buff.toString());                
                }                            
            }
            
        } catch (Exception ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {

            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (BigIpDecryptTab.OPTION_PROPERTY.equals(evt.getPropertyName())) {
                    setScan(tabbetOption.getScanProperty());
                    //System.out.println(getScan().getNotifyTypes() + ":" + getScan().getHighlightColor());
                    applyOptionProperty();  
                }
            }

        };
    }

    private void applyOptionProperty() {
        try {
            String configXML = Config.saveToXML(this.getProperty());
            getCallbacks().saveExtensionSetting("configXML", ConvertUtil.compressZlibBase64(configXML));

        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }        

    }

    private OptionProperty getProperty() {
        return this;
    }
        
    /* OptionProperty implements */
    private ScanProperty scanProperty = new ScanProperty();
    
    
    @Override
    public ScanProperty getScan() {
        return this.scanProperty;
    }

    @Override
    public void setScan(ScanProperty scan) {
        this.scanProperty = scan;
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
//        burp.StartBurp.main(args);
    }
    
                   
}
