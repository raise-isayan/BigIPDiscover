package passive;

import extension.burp.Severity;


/**
 *
 * @author isayan
 */
public interface ISignatureItem {

    /**
     * @return the enable
     */
    public boolean isEnable();

    /**
     * @param enable the enable to set
     */
    public void setEnable(boolean enable);

    /**
     * @return the issueName
     */
    public String getIssueName();

    /**
     * @return the serverity
     */
    public Severity getServerity();

}
