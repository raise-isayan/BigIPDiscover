package passive;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import extension.burp.BurpConfig;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author isayan
 */
public class Config extends BurpConfig {


    public static File getExtensionHomeDir() {
        return new File(BurpConfig.getUserHomeFile(), getExtensionDir());
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

    public static void loadFromJson(File fi, Map<String, String> option) throws IOException {
        GsonBuilder gsonBuilder = new GsonBuilder().serializeNulls();
        gsonBuilder = gsonBuilder.excludeFieldsWithoutExposeAnnotation();
        Gson gson = gsonBuilder.create();
        String jsonString = StringUtil.getStringUTF8(FileUtil.bytesFromFile(fi));
        JsonElement jsonRoot = JsonUtil.parse(jsonString);
        if (jsonRoot.isJsonObject()) {
            JsonObject jsonMap = jsonRoot.getAsJsonObject();    
            for (String memberName : jsonMap.keySet()) {
                option.put(memberName, jsonMap.get(memberName).toString());
            }
        }
    }

    public static void saveToJson(File fo, Map<String, String> option) throws IOException {
        GsonBuilder gsonBuilder = new GsonBuilder().serializeNulls();
        gsonBuilder = gsonBuilder.excludeFieldsWithoutExposeAnnotation();
        Gson gson = gsonBuilder.create();
        JsonObject jsonMap = new JsonObject();    
        for (String memberName : option.keySet()) {
            jsonMap.add(memberName, JsonUtil.parse(option.get(memberName)));
        }        
        String jsonString = gson.toJson(jsonMap);
        FileUtil.bytesToFile(StringUtil.getBytesUTF8(jsonString), fo);
    }
        
}

