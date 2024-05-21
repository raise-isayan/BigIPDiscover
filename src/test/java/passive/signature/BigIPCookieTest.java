package passive.signature;

import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class BigIPCookieTest {

    public BigIPCookieTest() {
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    private final static String REQ_TEST_FMT = "GET / HTTP/1.1\r\n"
            + "Host: www.example.com\r\n"
            + "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36\r\n"
            + "Cookie: %s\r\n"
            + "Connection: close\r\n";

    private final static String RES_TEST_FMT = "HTTP/1.1 200 OK\r\n"
            + "Content-Length: 0\r\n"
            + "Content-Type: text/html\r\n"
            + "Set-Cookie: %s\r\n";

    private final static String RES_TEST10_FMT = "HTTP/1.1 200 OK\r\n"
            + "Date: Sat, 03 Feb 2018 02:22:53 GMT\r\n"
            + "Server: Apache/2.4.10 (Debian)\r\n"
            + "Set-Cookie: TestCookie=test\r\n"
            + "Set-Cookie: BIGipServer2092=1677787402.36895.0000\r\n"
            + "Set-Cookie: m9q9XULEMwKPeMim=1526851379225347956\r\n"
            + "Vary: Accept-Encoding\r\n"
            + "Content-Length: 115\r\n"
            + "Connection: close\r\n"
            + "Content-Type: text/html; charset=UTF-8\r\n\r\n";

    private final static String RES_TEST11_FMT = "HTTP/1.1 200 OK\r\n"
            + "Date: Sat, 19 Jan 2019 02:49:15 GMT\r\n"
            + "Server: Apache/2.4.10 (Debian)\r\n"
            + "Set-Cookie: TestCookie=test\r\n"
            + "Set-Cookie: BIGipServer15722=rd5o00000000000000000000ffffc0000201o80\r\n"
            + "Set-Cookie: m9q9XULEMwKPeMim=43029390064855036802\r\n"
            + "Vary: Accept-Encoding\r\n"
            + "Content-Length: 116\r\n"
            + "Connection: close\r\n"
            + "Content-Type: text/html; charset=UTF-8\r\n\r\n";

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Req1() {
        System.out.println("BigIpEncrypt Req1");
        String req1 = String.format(REQ_TEST_FMT, "BIGipServer_aa_bb_cc=1677787402.36895.0000");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(true, req1);
        assertEquals("10.1.1.100:8080", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        String req2 = String.format(REQ_TEST_FMT, "aa_bb_cc=1677787402.36895.0000");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(true, req2);
        assertEquals("10.1.1.100:8080", bigIP2.get(0).getIPAddr());
        assertEquals(false, bigIP2.get(0).startsBIGipServer());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Req2() {
        System.out.println("BigIpEncrypt Req2");
        String req1 = String.format(REQ_TEST_FMT, "BIGipServer_aa_bb_cc=vi20010112000000000000000000000030.20480");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(true, req1);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        String req2 = String.format(REQ_TEST_FMT, "aa_bb_cc=vi20010112000000000000000000000030.20480");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(true, req2);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", bigIP2.get(0).getIPAddr());
        assertEquals(false, bigIP2.get(0).startsBIGipServer());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Req3() {
        System.out.println("BigIpEncrypt Req3");
        String req1 = String.format(REQ_TEST_FMT, "BIGipServer_aa_bb_cc=rd5o00000000000000000000ffffc0000201o80");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(true, req1);
        assertEquals("192.0.2.1:80", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        String req2 = String.format(REQ_TEST_FMT, "aa_bb_cc=rd5o00000000000000000000ffffc0000201o80");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(true, req2);
        assertEquals("192.0.2.1:80", bigIP2.get(0).getIPAddr());
        assertEquals(false, bigIP2.get(0).startsBIGipServer());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Req4() {
        System.out.println("BigIpEncrypt Req4");
        String req1 = String.format(REQ_TEST_FMT, "BIGipServer_aa_bb_cc=rd3o20010112000000000000000000000030o80");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(true, req1);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        String req2 = String.format(REQ_TEST_FMT, "aa_bb_cc=rd3o20010112000000000000000000000030o80");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(true, req2);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", bigIP2.get(0).getIPAddr());
        assertEquals(false, bigIP2.get(0).startsBIGipServer());

    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookieList_Req1() {
        System.out.println("BigIpEncrypt Req1");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseDecryptList(true, "BIGipServer_aa_bb_cc=1677787402.36895.0000", 0);
        assertEquals("10.1.1.100:8080", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseDecryptList(true, "aa_bb_cc=1677787402.36895.0000", 0);
        assertEquals("10.1.1.100:8080", bigIP2.get(0).getIPAddr());
        assertEquals(false, bigIP2.get(0).startsBIGipServer());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Res1() {
        System.out.println("BigIpEncrypt Res1");
        String res1 = String.format(RES_TEST_FMT, "BIGipServer_aa_bb_cc=1677787402.36895.0000");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, res1);
        assertEquals("10.1.1.100:8080", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        String res2 = String.format(RES_TEST_FMT, "aa_bb_cc=1677787402.36895.0000");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(false, res2);
        assertEquals("10.1.1.100:8080", bigIP2.get(0).getIPAddr());
        assertEquals(false, bigIP2.get(0).startsBIGipServer());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Res2() {
        System.out.println("BigIpEncrypt Res2");
        String res1 = String.format(RES_TEST_FMT, "BIGipServer_aa_bb_cc=vi20010112000000000000000000000030.20480");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, res1);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        String res2 = String.format(RES_TEST_FMT, "aa_bb_cc=vi20010112000000000000000000000030.20480");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(false, res2);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", bigIP2.get(0).getIPAddr());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Res3() {
        System.out.println("BigIpEncrypt Res3");
        String res1 = String.format(RES_TEST_FMT, "BIGipServer_aa_bb_cc=rd5o00000000000000000000ffffc0000201o80");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, res1);
        assertEquals("192.0.2.1:80", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        String res2 = String.format(RES_TEST_FMT, "aa_bb_cc=rd5o00000000000000000000ffffc0000201o80");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(false, res2);
        assertEquals("192.0.2.1:80", bigIP2.get(0).getIPAddr());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Res4() {
        System.out.println("BigIpEncrypt Res4");
        String res1 = String.format(RES_TEST_FMT, "BIGipServer_aa_bb_cc=rd3o20010112000000000000000000000030o80");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, res1);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());

        String res2 = String.format(RES_TEST_FMT, "aa_bb_cc=rd3o20010112000000000000000000000030o80");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(false, res2);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", bigIP2.get(0).getIPAddr());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Res10() {
        System.out.println("BigIpEncrypt Res10");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, RES_TEST10_FMT);
        assertEquals("10.1.1.100:8080", bigIP1.get(0).getIPAddr());
        assertEquals(true, bigIP1.get(0).isPrivateIP());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testBigIPCookie_Res11() {
        System.out.println("BigIpEncrypt Res11");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, RES_TEST11_FMT);
        assertEquals("192.0.2.1:80", bigIP1.get(0).getIPAddr());
        assertEquals(false, bigIP1.get(0).isPrivateIP());
        assertEquals(true, bigIP1.get(0).startsBIGipServer());
    }

    /**
     * Test of decrypt method, of class BigIPCookie.
     */
    @Test
    public void testDecrypt() {
        System.out.println("decrypt");
        String ip1 = BigIPCookieScan.decrypt("1677787402.36895.0000");
        assertEquals("10.1.1.100:8080", ip1);

        String ip2 = BigIPCookieScan.decrypt("vi20010112000000000000000000000030.20480");
        //  [2001:0112::0030]:80
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", ip2);

        String ip3 = BigIPCookieScan.decrypt("rd5o00000000000000000000ffffc0000201o80");
        assertEquals("192.0.2.1:80", ip3);

        String ip4 = BigIPCookieScan.decrypt("rd3o20010112000000000000000000000030o80");
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]:80", ip4);

    }

    /**
     * Test of decrypt2 method, of class BigIPCookie.
     */
    @Test
    public void testDecrypt2() {
        System.out.println("decrypt2");
        String ip1 = BigIPCookieScan.decrypt("10.1.1.100");
        assertEquals(null, ip1);

        String ip2 = BigIPCookieScan.decrypt("192.0.2.1");
        assertEquals(null, ip2);

    }

    /**
     * Test of start and End method, of class BigIPCookie.
     */
    @Test
    public void testStartEnd_Req1() {
        System.out.println("start and end req1");
        String req1 = String.format(REQ_TEST_FMT, "BIGipServer_aa_bb_cc=1677787402.36895.0000");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(true, req1);
        assertEquals("BIGipServer_aa_bb_cc=1677787402.36895.0000", req1.substring(bigIP1.get(0).start(), bigIP1.get(0).end()));

        String req2 = String.format(REQ_TEST_FMT, "aa_bb_cc=1677787402.36895.0000");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(true, req2);
        assertEquals("aa_bb_cc=1677787402.36895.0000", req2.substring(bigIP2.get(0).start(), bigIP2.get(0).end()));
    }

    /**
     * Test of start and End method, of class BigIPCookie.
     */
    @Test
    public void testStartEnd_Req2() {
        System.out.println("start and end req2");
        String req1 = String.format(REQ_TEST_FMT, "BIGipServer_aa_bb_cc=vi20010112000000000000000000000030.20480");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(true, req1);
        assertEquals("BIGipServer_aa_bb_cc=vi20010112000000000000000000000030.20480", req1.substring(bigIP1.get(0).start(), bigIP1.get(0).end()));

        String req2 = String.format(REQ_TEST_FMT, "aa_bb_cc=vi20010112000000000000000000000030.20480");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(true, req2);
        assertEquals("aa_bb_cc=vi20010112000000000000000000000030.20480", req2.substring(bigIP2.get(0).start(), bigIP2.get(0).end()));
    }

    /**
     * Test of start and End method, of class BigIPCookie.
     */
    @Test
    public void testStartEnd_Req3() {
        System.out.println("start and end req3");
        String req1 = String.format(REQ_TEST_FMT, "BIGipServer_aa_bb_cc=rd5o00000000000000000000ffffc0000201o80");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(true, req1);
        assertEquals("BIGipServer_aa_bb_cc=rd5o00000000000000000000ffffc0000201o80", req1.substring(bigIP1.get(0).start(), bigIP1.get(0).end()));

        String req2 = String.format(REQ_TEST_FMT, "aa_bb_cc=rd5o00000000000000000000ffffc0000201o80");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(true, req2);
        assertEquals("aa_bb_cc=rd5o00000000000000000000ffffc0000201o80", req2.substring(bigIP2.get(0).start(), bigIP2.get(0).end()));

    }

    /**
     * Test of start and End method, of class BigIPCookie.
     */
    @Test
    public void testStartEnd_Req4() {
        System.out.println("start and end req4");
        String req1 = String.format(REQ_TEST_FMT, "BIGipServer_aa_bb_cc=rd3o20010112000000000000000000000030o80");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(true, req1);
        assertEquals("BIGipServer_aa_bb_cc=rd3o20010112000000000000000000000030o80", req1.substring(bigIP1.get(0).start(), bigIP1.get(0).end()));

        String req2 = String.format(REQ_TEST_FMT, "aa_bb_cc=rd3o20010112000000000000000000000030o80");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(true, req2);
        assertEquals("aa_bb_cc=rd3o20010112000000000000000000000030o80", req2.substring(bigIP2.get(0).start(), bigIP2.get(0).end()));
    }

    /**
     * Test of start and End method, of class BigIPCookie.
     */
    @Test
    public void testStartEnd_Res1() {
        System.out.println("start and end res1");
        String res1 = String.format(RES_TEST_FMT, "BIGipServer_aa_bb_cc=1677787402.36895.0000");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, res1);
        assertEquals("BIGipServer_aa_bb_cc=1677787402.36895.0000", res1.substring(bigIP1.get(0).start(), bigIP1.get(0).end()));

        String res2 = String.format(RES_TEST_FMT, "aa_bb_cc=1677787402.36895.0000");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(false, res2);
        assertEquals("aa_bb_cc=1677787402.36895.0000", res2.substring(bigIP2.get(0).start(), bigIP2.get(0).end()));
    }

    /**
     * Test of start and End method, of class BigIPCookie.
     */
    @Test
    public void testStartEnd_Res2() {
        System.out.println("start and end res2");
        String res1 = String.format(RES_TEST_FMT, "BIGipServer_aa_bb_cc=vi20010112000000000000000000000030.20480");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, res1);
        assertEquals("BIGipServer_aa_bb_cc=vi20010112000000000000000000000030.20480", res1.substring(bigIP1.get(0).start(), bigIP1.get(0).end()));

        String res2 = String.format(RES_TEST_FMT, "aa_bb_cc=vi20010112000000000000000000000030.20480");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(false, res2);
        assertEquals("aa_bb_cc=vi20010112000000000000000000000030.20480", res2.substring(bigIP2.get(0).start(), bigIP2.get(0).end()));
    }

    /**
     * Test of start and End method, of class BigIPCookie.
     */
    @Test
    public void testStartEnd_Res3() {
        System.out.println("start and end res3");
        String res1 = String.format(RES_TEST_FMT, "BIGipServer_aa_bb_cc=rd5o00000000000000000000ffffc0000201o80");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, res1);
        assertEquals("BIGipServer_aa_bb_cc=rd5o00000000000000000000ffffc0000201o80", res1.substring(bigIP1.get(0).start(), bigIP1.get(0).end()));

        String res2 = String.format(RES_TEST_FMT, "aa_bb_cc=rd5o00000000000000000000ffffc0000201o80");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(false, res2);
        assertEquals("aa_bb_cc=rd5o00000000000000000000ffffc0000201o80", res2.substring(bigIP2.get(0).start(), bigIP2.get(0).end()));

    }

    /**
     * Test of start and End method, of class BigIPCookie.
     */
    @Test
    public void testStartEnd_Res4() {
        System.out.println("start and end res4");
        String res1 = String.format(RES_TEST_FMT, "BIGipServer_aa_bb_cc=rd3o20010112000000000000000000000030o80");
        List<BigIPIssueItem> bigIP1 = BigIPCookieScan.parseHeader(false, res1);
        assertEquals("BIGipServer_aa_bb_cc=rd3o20010112000000000000000000000030o80", res1.substring(bigIP1.get(0).start(), bigIP1.get(0).end()));

        String res2 = String.format(RES_TEST_FMT, "aa_bb_cc=rd3o20010112000000000000000000000030o80");
        List<BigIPIssueItem> bigIP2 = BigIPCookieScan.parseHeader(false, res2);
        assertEquals("aa_bb_cc=rd3o20010112000000000000000000000030o80", res2.substring(bigIP2.get(0).start(), bigIP2.get(0).end()));
    }

}
