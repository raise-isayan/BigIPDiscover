package passive.signature;

import com.google.gson.annotations.Expose;
import extend.view.base.MatchItem;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public class BigIPCookieProperty {

    @Expose
    private boolean scanRequest = true;

    public boolean getScanRequest() {
        return this.scanRequest;
    }

    public void setScanRequest(boolean value) {
        this.scanRequest = value;
    }

    @Expose
    private boolean scanResponse = true;

    public boolean getScanResponse() {
        return this.scanResponse;
    }

    public void setScanResponse(boolean value) {
        this.scanResponse = value;
    }

    @Expose
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

    @Expose
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

    @Expose
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

    public void setProperty(BigIPCookieProperty property) {
        this.scanRequest = property.scanRequest;
        this.scanResponse = property.scanResponse;
        this.detectionPrivateIP = property.detectionPrivateIP;
        this.notifyTypes = property.notifyTypes;
        this.highlightColor = property.highlightColor;
    }

}
