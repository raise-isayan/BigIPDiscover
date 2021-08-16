package burp;

import extension.burp.BurpExtenderImpl;
import passive.Config;
import passive.signature.BigIPCookie;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import passive.BigIPDiscover;
import passive.OptionProperty;

/**
 *
 * @author isayan
 */
public class BurpExtender extends BurpExtenderImpl implements IBurpExtender, IHttpListener, IExtensionStateListener {
    private final static Logger logger = Logger.getLogger(BurpExtender.class.getName());

    private final File CONFIG_FILE = new File(Config.getExtensionHomeDir(), Config.getExtensionFile());

    private final BigIPCookie signatureBigIP = new BigIPCookie();
    
    static {
        File logDir = Config.getExtensionHomeDir();
        logDir.mkdirs();
    }

    public BurpExtender() {
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                logger.log(Level.SEVERE, e.getMessage(), e);
            }
        });    
    }
    
    public static BurpExtender getInstance() {
        return BurpExtenderImpl.<BurpExtender>getInstance();
    }

    @Override
    /* IBurpExtender interface implements method */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        super.registerExtenderCallbacks(callbacks);
        callbacks.setExtensionName(String.format("%s v%s", BigIPDiscover.getProjectName(), BigIPDiscover.getVersion()));
        callbacks.addSuiteTab(this.signatureBigIP);
        callbacks.registerExtensionStateListener(this);
        Map<String, String> config = this.option.loadSignatureSetting();
        try {
            if (CONFIG_FILE.exists()) {
                Config.loadFromJson(CONFIG_FILE, config);
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        String configBigIPCookie = config.get(this.signatureBigIP.settingName());
        if (configBigIPCookie != null) {    
            this.signatureBigIP.saveSetting(configBigIPCookie);
        }

        // プロフェッショナル版の場合
        if (getBurpVersion().isProfessional()) {
            callbacks.registerScannerCheck(professionalPassiveScanCheck());
        } // フリー版の場合
        else {
            callbacks.registerHttpListener(this);
        }
    }

    private IScannerCheck professionalPassiveScanCheck() {        
        return signatureBigIP.passiveScanCheck();
    }

    // フリー版の実装
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if ((toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) && !messageIsRequest) {
            try {
                signatureBigIP.freePassiveScan(messageInfo);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    }

    private void applyOptionProperty() {
        try {
            Map<String, String> config = this.option.loadSignatureSetting();
            String configBigIPCookie = this.signatureBigIP.loadSetting();
            config.put(this.signatureBigIP.settingName(), configBigIPCookie);
            Config.saveToJson(CONFIG_FILE, config);
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

    @Override
    public void extensionUnloaded() {
        applyOptionProperty();
    }
        
}
