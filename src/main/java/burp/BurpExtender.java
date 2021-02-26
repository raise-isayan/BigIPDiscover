package burp;

import extension.burp.BurpExtenderImpl;
import extension.burp.NotifyType;
import passive.Config;
import passive.OptionProperty;
import passive.signature.BigIPCookieProperty;
import passive.IOptionProperty;
import passive.signature.BigIPCookieTab;
import passive.signature.BigIPCookie;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import passive.BigIPDiscover;
import passive.signature.BigIPIssueItem;

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl implements IBurpExtender, IHttpListener {
    private final static Logger logger = Logger.getLogger(BurpExtender.class.getName());

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
        callbacks.setExtensionName(String.format("%s v%s", BigIPDiscover.getProjectName(), BigIPDiscover.getVersion()));

        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
            }
        });
        callbacks.addSuiteTab(this.tabbetOption);
        try {
            if (CONFIG_FILE.exists()) {
                Config.loadFromJson(CONFIG_FILE, this.option);
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
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
                logger.log(Level.SEVERE, ex.getMessage(), ex);
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
            if (property.getNotifyTypes().contains(NotifyType.ITEM_HIGHLIGHT)) {
                messageInfo.setHighlight(property.getHighlightColor().toString());
            }
            if (this.getProperty().getBigIPCookieProperty().getNotifyTypes().contains(NotifyType.COMMENT)) {
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
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    private final OptionProperty option = new OptionProperty();

    public OptionProperty getProperty() {
        return this.option;
    }

}
