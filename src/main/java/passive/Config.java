package passive;

import extension.burp.BurpConfig;
import extension.helpers.json.JsonUtil;
import java.io.File;
import java.io.IOException;

/**
 *
 * @author isayan
 */
public class Config extends BurpConfig {


    public static File getExtensionHomeDir() {
        return new File(BurpConfig.getUserDirFile(), getExtensionDir());
    }

    public static String getExtensionDir() {
        return ".passiveplus";
    }

    public static String getExtensionFile() {
        return "BigIPDiscover.json";
    }

    public static String getUserDir() {
        return System.getProperties().getProperty("user.dir");
    }

    public static void saveToJson(File fo, OptionProperty option) throws IOException {
        JsonUtil.saveToJson(fo, option, true);
    }

    public static void loadFromJson(File fi, OptionProperty option) throws IOException {
        OptionProperty load = JsonUtil.loadFromJson(fi, OptionProperty.class, true);
        option.setProperty(load);
    }

}

