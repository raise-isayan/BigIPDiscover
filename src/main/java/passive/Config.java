package passive;

import extend.util.external.JsonUtil;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

/**
 *
 * @author isayan
 */
public class Config {
        
    public static String getUserHome() {
        return System.getProperties().getProperty("user.home");
    }

    public static File getExtensionHomeDir() {
        return new File(getUserHome(), getExtensionDir());
    }

    public static String getExtensionDir() {
        return ".BigIPDiscover";
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

