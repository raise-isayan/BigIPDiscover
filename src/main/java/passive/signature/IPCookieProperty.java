package passive.signature;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 *
 * @author isayan
 */
public class IPCookieProperty {

    @Expose
    @SerializedName("scanRequest")
    private boolean scanRequest = true;

    public boolean getScanRequest() {
        return this.scanRequest;
    }

    public void setScanRequest(boolean value) {
        this.scanRequest = value;
    }

    @Expose
    @SerializedName("scanResponse")
    private boolean scanResponse = true;

    public boolean getScanResponse() {
        return this.scanResponse;
    }

    public void setScanResponse(boolean value) {
        this.scanResponse = value;
    }

    @Expose
    @SerializedName("detectionPrivateIP")
    private boolean detectionPrivateIP = false;

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

    public void setProperty(IPCookieProperty property) {
        this.scanRequest = property.scanRequest;
        this.scanResponse = property.scanResponse;
        this.detectionPrivateIP = property.detectionPrivateIP;
    }
}
