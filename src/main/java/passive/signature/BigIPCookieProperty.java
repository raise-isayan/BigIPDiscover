package passive.signature;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import extend.view.base.MatchItem;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public class BigIPCookieProperty extends IPCookieProperty {

    @Expose
    @SerializedName("notifyTypes")
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
    @SerializedName("highlightColor")
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
        super.setProperty(property);
        this.notifyTypes = property.notifyTypes;
        this.highlightColor = property.highlightColor;
    }

}
