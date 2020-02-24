package passive.signature;

/**
 *
 * @author isayan
 */
public class BigIPIssueItem extends IPCookieIssueItem {

    private boolean startsBIGipServer = false;

    public boolean startsBIGipServer() {
        return this.startsBIGipServer;
    }

    /**
     * @param startsBIGipServer the startsBIGipServer to set
     */
    protected void setStartsBIGipServer(boolean startsBIGipServer) {
        this.startsBIGipServer = startsBIGipServer;
    }

}
