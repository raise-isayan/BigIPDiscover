package passive.signature;

/**
 *
 * @author isayan
 */
public interface ISignatureConfig {
   
    public String settingName();
    
    public void saveSetting(String value);

    public String loadSetting();
            
}
