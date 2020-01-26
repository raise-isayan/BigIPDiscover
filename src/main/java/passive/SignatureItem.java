package passive;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import burp.IScanIssue;
import burp.IScannerCheck;
import extend.view.base.MatchItem;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author raise.isayan
 */
public class SignatureItem<M extends IssueItem> implements ISignatureItem {

    public SignatureItem(String issueName, MatchItem.Severity serverity) {
        this.issueName = issueName;
        this.serverity = serverity;
    }

    private boolean enable = true;

    /**
     * @return the enable
     */
    @Override
    public boolean isEnable() {
        return this.enable;
    }

    /**
     * @param enable the enable to set
     */
    @Override
    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    private final String issueName;

    @Override
    public String getIssueName() {
        return issueName;
    }

    private final MatchItem.Severity serverity;

    @Override
    public MatchItem.Severity getServerity() {
        return serverity;
    }

    public IScanIssue makeScanIssue(IHttpRequestResponse messageInfo, List<M> issueItem) {
        return null;
    }

    public IScannerCheck passiveScanCheck() {
        return new PassiveCheckAdapter();
    }

    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse baseRequestResponse, List<M> issueList) {
        List<int[]> requestMarkers = new ArrayList<>();
        List<int[]> responseMarkers = new ArrayList<>();
        for (IssueItem issue : issueList) {
            if (issue.isMessageIsRequest()) {
                requestMarkers.add(new int [] { issue.start(), issue.end() });
            }
            else {
                responseMarkers.add(new int [] { issue.start(), issue.end() });            
            }
        }
        List<int[]> applyRequestMarkers = (requestMarkers.size() > 0) ? requestMarkers : null;
        List<int[]> applyResponseMarkers = (responseMarkers.size() > 0) ? responseMarkers : null;
        
        return BurpExtender.getCallbacks().applyMarkers(baseRequestResponse, applyRequestMarkers, applyResponseMarkers);            
    }
        
}
