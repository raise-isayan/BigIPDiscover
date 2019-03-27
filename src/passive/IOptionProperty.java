package passive;

import passive.signature.BigIPCookieProperty;

/**
 *
 * @author isayan
 */
public interface IOptionProperty {

    public final static String BIGIP_COOKIE_PROPERTY = "BigIPCookieProperty";
    
    public BigIPCookieProperty getBigIPCookieProperty();

    public void setBigIPCookieProperty(BigIPCookieProperty scan);

}
