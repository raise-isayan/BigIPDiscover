package passive;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author raise.isayan
 */
public class OptionProperty implements IOptionProperty {

    private final Map<String, String> config = new HashMap(); 
    
    @Override
    public void saveSignatureSetting(final Map<String, String> value) {
        this.config.putAll(value);
    }

    @Override
    public Map<String, String> loadSignatureSetting() {
        return this.config;
    }
    
}
