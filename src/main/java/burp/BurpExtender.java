package burp;

import passive.Config;
import passive.OptionProperty;
import passive.signature.BigIPCookieProperty;
import passive.IOptionProperty;
import passive.signature.BigIPCookieTab;
import passive.signature.BigIPCookie;
import extend.util.IpUtil;
import extend.view.base.MatchItem;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import passive.signature.BigIPIssueItem;

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl implements IBurpExtender, IHttpListener {

    private final File CONFIG_FILE = new File(Config.getExtensionHomeDir(), Config.getExtensionFile());
    
    private final BigIPCookieTab tabbetOption = new BigIPCookieTab();

    static {
        File logDir = Config.getExtensionHomeDir();
        logDir.mkdirs();
    }
        
    public static BurpExtender getInstance() {
        return BurpExtenderImpl.<BurpExtender>getInstance();
    }

    @Override
    /* IBurpExtender interface implements method */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        super.registerExtenderCallbacks(callbacks);
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, e);
            }
        });
        callbacks.addSuiteTab(this.tabbetOption);
        try {
            if (CONFIG_FILE.exists()) {
                Config.loadFromJson(CONFIG_FILE, this.option);
            }
        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }

        this.tabbetOption.setProperty(this.getProperty().getBigIPCookieProperty());
        this.tabbetOption.addPropertyChangeListener(newPropertyChangeListener());

        // プロフェッショナル版の場合
        if (getBurpVersion().isProfessional()) {
            callbacks.registerScannerCheck(professionalPassiveScanCheck());
        } // フリー版の場合
        else {
            callbacks.registerHttpListener(this);
        }

    }

    private IScannerCheck professionalPassiveScanCheck() {
        BigIPCookieProperty property = this.getProperty().getBigIPCookieProperty();
        final BigIPCookie bigip = new BigIPCookie(property);
        return bigip.passiveScanCheck();
    }

    // フリー版の実装
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if ((toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) && !messageIsRequest) {
            try {
                freePassiveScan(messageInfo);
            } catch (Exception ex) {
                Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void freePassiveScan(IHttpRequestResponse messageInfo) {
        BigIPCookieProperty property = this.getProperty().getBigIPCookieProperty();
        List<BigIPIssueItem> bigIpList = new ArrayList<>();
        final BigIPCookie bigip = new BigIPCookie(property);
        // Response判定
        if (property.getScanResponse() && messageInfo.getResponse() != null) {
            bigIpList.addAll(bigip.parseMessage(false, messageInfo.getResponse()));
        }
        // Request判定
        if (property.getScanRequest() && messageInfo.getRequest() != null) {
            bigIpList.addAll(bigip.parseMessage(true, messageInfo.getRequest()));                
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
            if (property.getNotifyTypes().contains(MatchItem.NotifyType.ITEM_HIGHLIGHT)) {
                messageInfo.setHighlight(property.getHighlightColor().toString());
            }
            if (this.getProperty().getBigIPCookieProperty().getNotifyTypes().contains(MatchItem.NotifyType.COMMENT)) {
                messageInfo.setComment(buff.toString());
            }
        }
    }

    public PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {

            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (IOptionProperty.BIGIP_COOKIE_PROPERTY.equals(evt.getPropertyName())) {
                    getProperty().setBigIPCookieProperty(tabbetOption.getProperty());
                    applyOptionProperty();
                }
            }

        };
    }

    private void applyOptionProperty() {
        try {
            Config.saveToJson(CONFIG_FILE, this.option);
        } catch (IOException ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private final OptionProperty option = new OptionProperty();

    public OptionProperty getProperty() {
        return this.option;
    }

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

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

            String bigIPaddr = BigIPCookie.decrypt(encrypt_value);
            System.out.println("IP addres: " + bigIPaddr);
            System.out.println("PrivateIP: " + IpUtil.isPrivateIP(bigIPaddr));
            System.out.println("LinkLocalIP: " + IpUtil.isLinkLocalIP(bigIPaddr));

        } catch (Exception ex) {
            String errmsg = String.format("%s: %s", ex.getClass().getName(), ex.getMessage());
            System.out.println(errmsg);
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
            usage();
        }
    }

    private static void usage() {
        final String projname = BUNDLE.getString("projname");
        System.out.println(String.format("Usage: java -jar %s.jar -d <encrypt>", projname));
        System.out.println(String.format("   ex: java -jar %s.jar -d BIGipServer16122=1677787402.36895.0000", projname));
    }

}
