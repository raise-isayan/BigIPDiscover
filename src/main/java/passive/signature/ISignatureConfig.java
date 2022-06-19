package passive.signature;

/**
 *
 * @author isayan
 */
public interface ISignatureConfig {

    public String getIssueName();
    
    public String loadConfig();

    public void saveConfig(String config);
    
}
