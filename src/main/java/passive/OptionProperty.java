package passive;

import extension.burp.IOptionProperty;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author raise.isayan
 */
public class OptionProperty implements IOptionProperty {

    private final Map<String, String> config = new HashMap();

    @Override
    public void saveConfigSetting(Map<String, String> map) {
        this.config.putAll(map);
    }

    @Override
    public Map<String, String> loadConfigSetting() {
        return this.config;
    }

}
