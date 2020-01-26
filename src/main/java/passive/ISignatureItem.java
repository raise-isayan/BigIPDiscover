package passive;

import extend.view.base.MatchItem;

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
    public MatchItem.Severity getServerity();
    
}
