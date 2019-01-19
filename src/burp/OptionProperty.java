package burp;

import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author raise.isayan
 */
@XmlRootElement(name = "bigip")
public class OptionProperty implements IOptionProperty {

    /* IOptionProperty implements */
    private final ScanProperty scanProperty = new ScanProperty();

    @Override
    public ScanProperty getScan() {
        return this.scanProperty;
    }

    @Override
    public void setScan(ScanProperty scan) {
        this.scanProperty.setProperty(scan);
    }

    public void setProperty(OptionProperty property) {
        this.setScan(property.getScan());
    }

}
