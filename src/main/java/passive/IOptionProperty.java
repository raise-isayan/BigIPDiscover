package passive;

import java.util.Map;

/**
 *
 * @author isayan
 */
public interface IOptionProperty {

    public void saveSignatureSetting(final Map<String, String> value);

    public Map<String, String> loadSignatureSetting();

}
