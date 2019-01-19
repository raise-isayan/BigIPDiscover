package burp;

import passive.signature.BigIPCookie;
import extend.util.ConvertUtil;
import extend.util.IpUtil;
import extend.view.base.MatchItem;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl implements IBurpExtender, IHttpListener {

    private final BigIpDecryptTab tabbetOption = new BigIpDecryptTab();
    private boolean burpProfessional = false;

    public static BurpExtender getInstance() {
        return BurpExtenderImpl.<BurpExtender>getInstance();
    }

    public boolean isProfessional() {
        return this.burpProfessional;
    }

    @Override
    /* IBurpExtender interface implements method */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        super.registerExtenderCallbacks(callbacks);
        callbacks.addSuiteTab(this.tabbetOption);
        this.burpProfessional = getBurpVersion().isProfessional();
        try {
            String configXML = getCallbacks().loadExtensionSetting("configXML");
            if (configXML != null) {
                Config.loadFromXml(ConvertUtil.decompressZlibBase64(configXML), this.getProperty());
            }
        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }

        this.tabbetOption.setScanProperty(this.getProperty().getScan());
        this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());

        // プロフェッショナル版の場合
        if (this.burpProfessional) {
            callbacks.registerScannerCheck(professionalPassiveScanCheck());
        } // フリー版の場合
        else {
            callbacks.registerHttpListener(this);
        }

    }

    private IScannerCheck professionalPassiveScanCheck() {
        BigIPCookie bigip = new BigIPCookie(this.getProperty());
        return bigip.passiveScanCheck();
    }

    // フリー版の実装
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if ((toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) && !messageIsRequest) {
            freePassiveScan(messageInfo);
        }
    }

    public void freePassiveScan(IHttpRequestResponse messageInfo) {
        try {
            List<BigIpDecrypt> bigIpList = null;
            // Response判定
            if (bigIpList == null && this.getProperty().getScan().getScanResponse() && messageInfo.getResponse() != null) {
                // ヘッダのみ抽出（逆に遅くなってるかも？）
                IResponseInfo resInfo = BurpExtender.getHelpers().analyzeResponse(messageInfo.getResponse());
                byte resHeader[] = Arrays.copyOfRange(messageInfo.getResponse(), 0, resInfo.getBodyOffset());
                bigIpList = BigIpDecrypt.parseMessage(false, resHeader);
            }
            // Request判定
            if (bigIpList == null && this.getProperty().getScan().getScanRequest() && messageInfo.getRequest() != null) {
                // ヘッダのみ抽出（逆に遅くなってるかも？）
                IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(messageInfo.getRequest());
                byte reqHeader[] = Arrays.copyOfRange(messageInfo.getRequest(), 0, reqInfo.getBodyOffset());
                bigIpList = BigIpDecrypt.parseMessage(true, reqHeader);
            }
            StringBuilder buff = new StringBuilder();
            for (int i = 0; i < bigIpList.size(); i++) {
                BigIpDecrypt item = bigIpList.get(i);
                //System.out.println("bigip:" + bigIpList[i].getEncryptCookie() + "=" + bigIpList[i].getIPAddr());
                // Private IP Only にチェックがついていてPrivate IPで無い場合はスキップ
                if (this.getProperty().getScan().isDetectionPrivateIP() && !item.isPrivateIP()) {
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
                ScanProperty scan = this.getProperty().getScan();
                if (scan.getNotifyTypes().contains(MatchItem.NotifyType.ITEM_HIGHLIGHT)) {
                    messageInfo.setHighlight(scan.getHighlightColor().toString());
                }
                if (this.getProperty().getScan().getNotifyTypes().contains(MatchItem.NotifyType.COMMENT)) {
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
                if (IOptionProperty.SCAN_PROPERTY.equals(evt.getPropertyName())) {
                    getProperty().setScan(tabbetOption.getScanProperty());
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

    private final IOptionProperty property = new OptionProperty();

    public IOptionProperty getProperty() {
        return this.property;
    }

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/release");

    private static String getVersion() {
        return BUNDLE.getString("version");
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            String encrypt_value = null;
            for (int i = 0; i < args.length; i += 2) {
                String[] param = Arrays.copyOfRange(args, i, args.length);
                if (param.length > 1) {
                    if ("-d".equals(param[0])) {
                        encrypt_value = param[1];
                    }
                } else if (param.length > 0) {
                    if ("-v".equals(param[0])) {
                        System.out.print("Version: " + getVersion());
                        System.exit(0);
                    }
                    if ("-h".equals(param[0])) {
                        usage();
                        System.exit(0);
                    }

                } else {
                    throw new IllegalArgumentException("argment err:" + String.join(" ", param));
                }
            }

            // 必須チェック
            if (encrypt_value == null) {
                System.out.println("-d argument err ");
                usage();
                return;
            }

            String bigIPaddr = BigIpDecrypt.decrypt(encrypt_value);
            System.out.println("IP addres: " + bigIPaddr);
            System.out.println("PrivateIP: " + IpUtil.isPrivateIP(bigIPaddr));

        } catch (Exception ex) {
            String errmsg = String.format("%s: %s", ex.getClass().getName(), ex.getMessage());
            System.out.println(errmsg);
            Logger.getLogger(BigIpDecrypt.class.getName()).log(Level.SEVERE, null, ex);
            usage();
        }
    }

    private static void usage() {
        final String projname = BUNDLE.getString("projname");
        System.out.println(String.format("Usage: java -jar %s.jar -d <encrypt>", projname));
        System.out.println(String.format("   ex: java -jar %s.jar -d BIGipServer16122=1677787402.36895.0000", projname));
    }

}
