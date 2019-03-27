package passive;

import passive.signature.BigIPCookieProperty;
import passive.IOptionProperty;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author raise.isayan
 */
@XmlRootElement(name = "bigip")
public class OptionProperty implements IOptionProperty {

    /* IOptionProperty implements */
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
