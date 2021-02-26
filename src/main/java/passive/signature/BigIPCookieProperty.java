package passive.signature;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import extension.burp.HighlightColor;
import extension.burp.NotifyType;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public class BigIPCookieProperty extends IPCookieProperty {

    @Expose
    @SerializedName("notifyTypes")
    private EnumSet<NotifyType> notifyTypes = EnumSet.allOf(NotifyType.class);

    /**
     * @return the notifyTypes
     */
    public EnumSet<NotifyType> getNotifyTypes() {
        return this.notifyTypes;
    }

    /**
     * @param notifyTypes the notifyType to set
     */
    public void setNotifyTypes(EnumSet<NotifyType> notifyTypes) {
        this.notifyTypes = notifyTypes;
    }

    @Expose
    @SerializedName("highlightColor")
    private HighlightColor highlightColor = HighlightColor.RED;

    /**
     * @return the highlightColor
     */
    public HighlightColor getHighlightColor() {
        return this.highlightColor;
    }

    /**
     * @param highlightColor the highlightColor to set
     */
    public void setHighlightColor(HighlightColor highlightColor) {
        this.highlightColor = highlightColor;
    }
    
    public void setProperty(BigIPCookieProperty property) {
        super.setProperty(property);
        this.notifyTypes = property.notifyTypes;
        this.highlightColor = property.highlightColor;
    }

}
