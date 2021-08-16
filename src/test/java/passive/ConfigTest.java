package passive;

import com.google.gson.JsonElement;
import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import extension.helpers.json.JsonUtil;
import java.io.File;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import passive.signature.BigIPCookie;

/**
 *
 * @author isayan
 */
public class ConfigTest {
    
    public ConfigTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

   /**
     * Test of mapFromJson method, of class Config.
     */
    @Test
    public void testMapFromJson() throws Exception {
        System.out.println("mapFromJson");
        URL testURL = this.getClass().getResource("/resources/BigIPDiscover.json");
        Map<String, String> option = new HashMap<>();
        Config.loadFromJson(new File(testURL.toURI()), option);
        System.out.println("Map:" + option);
        System.out.println("Key:" + BigIPCookie.BIGIP_COOKIE_PROPERTY);
        System.out.println("Val:" + option.get(BigIPCookie.BIGIP_COOKIE_PROPERTY));
        File tmp = File.createTempFile("BigIPDiscover", "json");
        System.out.println(tmp.getAbsolutePath());
        Config.saveToJson(tmp, option);
    }
    
}
