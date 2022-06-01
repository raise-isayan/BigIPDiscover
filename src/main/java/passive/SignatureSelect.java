package passive;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import extension.burp.Severity;

/**
 *
 * @author isayan
 */
public class SignatureSelect {

    public SignatureSelect(String issueName, Severity serverity) {
        this.issueName = issueName;
        this.serverity = serverity;
    }

    @Expose
    @SerializedName("selected")
    private boolean selected = true;

    /**
     * @return the selected
     */
    public boolean isSelected() {
        return this.selected;
    }

    /**
     * @param selected the selected to set
     */
    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    @Expose
    @SerializedName("issueName")
    private final String issueName;

    public String getIssueName() {
        return issueName;
    }

    private final Severity serverity;

    public Severity getServerity() {
        return serverity;
    }


}
