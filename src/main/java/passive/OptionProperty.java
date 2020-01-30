package passive;

import com.google.gson.annotations.Expose;
import passive.signature.BigIPCookieProperty;

/**
 *
 * @author raise.isayan
 */
public class OptionProperty implements IOptionProperty {

    /* IOptionProperty implements */
    @Expose
    private final BigIPCookieProperty bigipCookieProperty = new BigIPCookieProperty();

    @Override
    public BigIPCookieProperty getBigIPCookieProperty() {
        return this.bigipCookieProperty;
    }

    @Override
    public void setBigIPCookieProperty(BigIPCookieProperty property) {
        this.bigipCookieProperty.setProperty(property);
    }

    public void setProperty(OptionProperty property) {
        this.setBigIPCookieProperty(property.getBigIPCookieProperty());
    }

}
