package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import extension.burp.BurpExtensionImpl;
import static extension.burp.BurpExtensionImpl.api;
import extension.burp.IBurpTab;
import extension.burp.IPropertyConfig;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.Map;
import java.util.logging.Logger;
import passive.OptionProperty;
import passive.signature.BigIPCookieScan;
import passive.signature.BigIPCookieSignature;
import passive.signature.BigIPCookieTab;

/**
 *
 * @author isayan
 */
public class BurpExtension extends BurpExtensionImpl implements HttpHandler, ExtensionUnloadingHandler {

    private final static Logger logger = Logger.getLogger(BurpExtension.class.getName());

    private final BigIPCookieTab tabBigIPCookie = new BigIPCookieTab();

    private final BigIPCookieSignature signature = new BigIPCookieSignature();

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    @Override
    public void initialize(MontoyaApi api) {
        super.initialize(api);
        api().extension().setName(BUNDLE.getString("projname"));
        IBurpTab tab = this.signature.getBurpTab();
        if (tab != null) {
            api().userInterface().registerSuiteTab(tab.getTabCaption(), tab.getUiComponent());
            IPropertyConfig config = this.signature.getSignatureConfig();
            if (config != null) {
                Map<String, String> settings = this.option.loadConfigSetting();
                Preferences pref = api().persistence().preferences();
                String value = pref.getString(BigIPCookieScan.SIGNATURE_PROPERTY);
                settings.put(BigIPCookieScan.SIGNATURE_PROPERTY, value == null ? config.defaultSetting() : value);
                String settingValue = settings.getOrDefault(config.getSettingName(), config.defaultSetting());
                config.saveSetting(settingValue);
                tab.getUiComponent().addPropertyChangeListener(config.getSettingName(), newPropertyChangeListener());
            }
        }
        api().scanner().registerScanCheck(this.signature.getSignatureScan().passiveScanCheck());
        api.http().registerHttpHandler(this);
        api.extension().registerUnloadingHandler(this);
        this.tabBigIPCookie.addPropertyChangeListener(newPropertyChangeListener());
    }

    @Override
    public void extensionUnloaded() {
        this.applyOptionProperty();
    }

    public PropertyChangeListener newPropertyChangeListener() {
        return new PropertyChangeListener() {

            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                IPropertyConfig config = signature.getSignatureConfig();
                if (config != null) {
                    if (config.getSettingName().equals(evt.getPropertyName())) {
                        Map<String, String> settings = option.loadConfigSetting();
                        settings.put(config.getSettingName(), config.loadSetting());
                        applyOptionProperty();
                    }
                }
            }
        };
    }

    private final OptionProperty option = new OptionProperty();

    public OptionProperty getProperty() {
        return this.option;
    }

    private void applyOptionProperty() {
        Map<String, String> settings = this.option.loadConfigSetting();
        Preferences pref = api().persistence().preferences();
        for (String key : settings.keySet()) {
            pref.setString(key, settings.get(key));
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent, requestToBeSent.annotations());
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        ToolSource toolSource = responseReceived.toolSource();
        if (toolSource.isFromTool(ToolType.REPEATER)) {
//            api().siteMap().add(HttpRequestResponse.httpRequestResponse(responseReceived.initiatingRequest(), responseReceived));
            ScanCheck scan = this.signature.getSignatureScan().passiveScanCheck();
            AuditResult audit = scan.passiveAudit(HttpRequestResponse.httpRequestResponse(responseReceived.initiatingRequest(), responseReceived));
            BurpExtension.helpers().outPrintln("issue:" + responseReceived.initiatingRequest().url() + "." + audit.auditIssues().size());
            for (AuditIssue auditIssue : audit.auditIssues()) {
                api().siteMap().add(auditIssue);
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived, responseReceived.annotations());
    }

}
