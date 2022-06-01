package passive;

import burp.ITab;
import extension.burp.IPropertyConfig;
import extension.burp.Severity;

/**
 *
 * @author isayan
 */
public class SignatureItem extends SignatureSelect {

    public SignatureItem(SignatureScanBase<? extends IssueItem> item, Severity serverity) {
        super(item.getIssueName(), serverity);
        this.item = item;
    }

    public char getSortOrder() {
        return 'z';
    }

    private final SignatureScanBase<? extends IssueItem> item;

    public SignatureScanBase<? extends IssueItem> getSignatureScan() {
        return item;
    }

    public ITab getBurpTab() {
        if (item instanceof ITab) {
            return (ITab) item;
        } else {
            return null;
        }
    }

    public IPropertyConfig getSignatureConfig() {
        if (item instanceof IPropertyConfig) {
            return (IPropertyConfig) item;
        } else {
            return null;
        }
    }

}
