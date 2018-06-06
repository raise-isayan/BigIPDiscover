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

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl implements IBurpExtender, IHttpListener, OptionProperty {
    private final BigIpDecryptTab tabbetOption = new BigIpDecryptTab();
    private boolean burpProfessional = false;
    
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
                BigIpDecrypt [] bigIpList = new BigIpDecrypt[0];
                // Response判定
                if (bigIpList.length == 0 && getScan().getScanResponse() && baseRequestResponse.getResponse() != null) {
                    // ヘッダのみ抽出（逆に遅くなってるかも？）
                    IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(baseRequestResponse.getResponse());
                    byte resHeader [] = Arrays.copyOfRange(baseRequestResponse.getResponse(), 0, resInfo.getBodyOffset());
                    bigIpList = BigIpDecrypt.parseDecrypts(false, resHeader);
                }
                // Request判定
                if (bigIpList.length == 0 && getScan().getScanRequest() && baseRequestResponse.getRequest() != null) {
                    // ヘッダのみ抽出（逆に遅くなってるかも？）
                    IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(baseRequestResponse.getResponse());
                    byte reqHeader [] = Arrays.copyOfRange(baseRequestResponse.getResponse(), 0, reqInfo.getBodyOffset());
                    bigIpList = BigIpDecrypt.parseDecrypts(true, reqHeader);                    
                }
                List<BigIpDecrypt> privateIPList = new ArrayList<>();                
                List<int []> responseMarkers = new ArrayList<>();                
                for (int i = 0; i < bigIpList.length; i++) {
                    if (bigIpList[i].isPrivateIP()) {
                        privateIPList.add(bigIpList[i]);
                        responseMarkers.add(new int[]{ bigIpList[i].start(), bigIpList[i].end()});
                    }                                                            
                }
                IHttpRequestResponseWithMarkers messageInfoMark = getCallbacks().applyMarkers(baseRequestResponse, null, responseMarkers);
                if (privateIPList.size() > 0) {
                    List<IScanIssue> issues = new ArrayList<>();
                    issues.add(makeIssue(privateIPList, messageInfoMark));
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

    public IScanIssue makeIssue(final  List<BigIpDecrypt> privateIPList, final IHttpRequestResponse messageInfo) {

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
                return "Information";
            }

            @Override
            public String getConfidence() {
                return "Certain";            
            }

            @Override
            public String getIssueBackground() {
                final String ISSUE_BACKGROUND =  "\r\n"
                    + "https://www.owasp.org/index.php/SCG_D_BIGIP<br />"
                    + "https://support.f5.com/csp/article/K6917<br />"
                    + "Examples.<br />"
                    + "  BIGipServer<pool_name>=1677787402.36895.0000<br />" 
                    + "  BIGipServer<pool_name>=vi20010112000000000000000000000030.20480<br />"
                    + "  BIGipServer<pool_name>=rd5o00000000000000000000ffffc0000201o80<br />" 
                    + "  BIGipServer<pool_name>=rd3o20010112000000000000000000000030o80<br />";
                return ISSUE_BACKGROUND;
            }

            @Override
            public String getRemediationBackground() {
                final String REMEDIATION_BACKGROUND =  "\r\n"
                    + "https://support.f5.com/csp/article/K6917\r\n";
                return REMEDIATION_BACKGROUND;
            }

            @Override
            public String getIssueDetail() {
                StringBuilder buff = new StringBuilder();
                for (BigIpDecrypt privateIP : privateIPList) {
                    buff.append(String.format("* cookie: %s\r\nip address:%s", privateIP.getEncryptCookie(), privateIP.getIPAddr()));
                    buff.append("\r\n");
                }
                return buff.toString();
            }

            @Override
            public String getRemediationDetail() {
                return "omission";
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
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo.getResponse());
                byte reqHeader [] = Arrays.copyOfRange(messageInfo.getResponse(), 0, reqInfo.getBodyOffset());
                bigIpList = BigIpDecrypt.parseDecrypts(true, reqHeader);
            }
            StringBuilder buff = new StringBuilder();
            for (int i = 0; i < bigIpList.length; i++) {
                if (bigIpList[i].isPrivateIP()) {
                    if (buff.length() == 0) {
                        buff.append("BigIP:");
                    }
                    else {
                        buff.append(", ");                    
                    }
                    buff.append(bigIpList[i].getIPAddr());                                
                }
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
            ex.printStackTrace();
        }
    }
    
    public PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {

            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (BigIpDecryptTab.OPTION_PROPERTY.equals(evt.getPropertyName())) {
                    setScan(tabbetOption.getScanProperty());
                    System.out.println(getScan().getNotifyTypes());
                    System.out.println(getScan().getHighlightColor());
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
        
                   
}
