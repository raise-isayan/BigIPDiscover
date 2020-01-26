package extend.util.external;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author isayan
 */
public class JsonUtilTest {

    public JsonUtilTest() {
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
     * Test of stringify method, of class JsonUtil.
     */
    @Test
    public void testStringify() {
        System.out.println("stringify");
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("abc", 123);
        jsonObject.addProperty("def", "test");
        String expResult = "{\"abc\":123,\"def\":\"test\"}";
        String result = JsonUtil.stringify(jsonObject);
        assertEquals(expResult, result);
    }

    /**
     * Test of parse method, of class JsonUtil.
     */
    @Test
    public void testParse() {
        System.out.println("parse");
        String jsonElementString = "{ \n \"abc\": 123, \n \"def\": \"test\" }";
        JsonElement result = JsonUtil.parse(jsonElementString);
        assertEquals(true, result.isJsonObject());
        assertEquals(true, result.getAsJsonObject().has("abc"));
        assertEquals(false, result.getAsJsonObject().has("xyz"));
    }

    /**
     * Test of prettyJson method, of class JsonUtil.
     */
    @Test
    public void testPrettyJSON_String_boolean() {
        System.out.println("prettyJSON");
        {
            String jsonElementString = "{ \n \"abc\": 123, \n \"def\": \"test\" }";
            boolean pretty = false;
            String expResult = "{\"abc\":123,\"def\":\"test\"}";
            String result = JsonUtil.prettyJson(jsonElementString, pretty);
            assertEquals(expResult, result);
        }
        {
            try {
                String jsonElementString = "<html>test</test>";
                boolean pretty = false;
                String expResult = "{\"abc\":123,\"def\":\"test\"}";
                String result = JsonUtil.prettyJson(jsonElementString, pretty);
                fail();
            } catch (JsonSyntaxException ex) {
                assertTrue(true);
            }
        }
    }

    /**
     * Test of prettyJson method, of class JsonUtil.
     */
    @Test
    public void testPrettyJSON_JsonElement_boolean() {
        System.out.println("prettyJSON");
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("abc", 123);
        jsonObject.addProperty("def", "test");
        boolean pretty = false;
        String expResult = "{\"abc\":123,\"def\":\"test\"}";
        String result = JsonUtil.prettyJson(jsonObject, pretty);
        assertEquals(expResult, result);
    }

    @Test
    public void testGson() {
        System.out.println("gson");        
    }
    
    
}
