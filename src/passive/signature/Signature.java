package passive.signature;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;

/**
 *
 * @author isayan
 */
public interface Signature<M> {

    public IScanIssue makeScanIssue(final IHttpRequestResponse messageInfo, final M issue);
        
    public IScannerCheck passiveScanCheck();
    
}
