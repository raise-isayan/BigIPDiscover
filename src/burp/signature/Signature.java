/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.signature;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import java.util.List;

/**
 *
 * @author isayan
 */
public interface Signature<M> {

    public IScanIssue makeScanIssue(final IHttpRequestResponse messageInfo, final List<M> list);
        
    public IScannerCheck passiveScanCheck();
    
}
