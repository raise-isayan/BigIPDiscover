package passive.signature;

import extend.view.base.MatchItem;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public class BigIPCookieProperty {

    private boolean scanRequest = true;

    public boolean getScanRequest() {
        return this.scanRequest;
    }

    public void setScanRequest(boolean value) {
        this.scanRequest = value;
    }

    private boolean scanResponse = true;

    public boolean getScanResponse() {
        return this.scanResponse;
    }

    public void setScanResponse(boolean value) {
        this.scanResponse = value;
    }

    private boolean detectionPrivateIP = true;

    /**
     * @return the detectionPrivateIP
     */
    public boolean isDetectionPrivateIP() {
        return detectionPrivateIP;
    }

    /**
     * @param detectionPrivateIP the detectionPrivateIP to set
     */
    public void setDetectionPrivateIP(boolean detectionPrivateIP) {
        this.detectionPrivateIP = detectionPrivateIP;
    }

    private EnumSet<MatchItem.NotifyType> notifyTypes = EnumSet.allOf(MatchItem.NotifyType.class);

    /**
     * @return the notifyTypes
     */
    public EnumSet<MatchItem.NotifyType> getNotifyTypes() {
        return this.notifyTypes;
    }

    /**
     * @param notifyTypes the notifyType to set
     */
    public void setNotifyTypes(EnumSet<MatchItem.NotifyType> notifyTypes) {
        this.notifyTypes = notifyTypes;
    }

    private MatchItem.HighlightColor highlightColor = MatchItem.HighlightColor.RED;

    /**
     * @return the highlightColor
     */
    public MatchItem.HighlightColor getHighlightColor() {
        return this.highlightColor;
    }

    /**
     * @param highlightColor the highlightColor to set
     */
    public void setHighlightColor(MatchItem.HighlightColor highlightColor) {
        this.highlightColor = highlightColor;
    }

    public void setProperty(BigIPCookieProperty scan) {
        this.scanRequest = scan.scanRequest;
        this.scanResponse = scan.scanResponse;
        this.detectionPrivateIP = scan.detectionPrivateIP;
        this.notifyTypes = scan.notifyTypes;
        this.highlightColor = scan.highlightColor;
    }

}
