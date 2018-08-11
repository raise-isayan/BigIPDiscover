/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.nio.ByteOrder;
import java.text.ParseException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author t.isayama
 */
public class IpUtilTest {
    
    public IpUtilTest() {
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
     * Test of isPrivateIP method, of class IpUtil.
     */
    @Test
    public void testIsPrivateIP() {
        System.out.println("isPrivateIP");
        try {
            // class A Private IP
            assertEquals(IpUtil.isPrivateIP("10.168.2.1"), true);
            // class B Private IP
            assertEquals(IpUtil.isPrivateIP("172.16.2.1"), true);
            // class C Private IP
            assertEquals(IpUtil.isPrivateIP("192.168.2.1"), true);
            
            assertEquals(IpUtil.isPrivateIP("8.8.8.8"), false);

            assertEquals(IpUtil.isPrivateIP("1.1.1.1"), false);

            assertEquals(IpUtil.isPrivateIP("255.255.255.1"), false);

        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    /**
     * Test of isPrivateIP method, of class IpUtil.
     */
    @Test
    public void testIsPrivateIP2() {
        System.out.println("isPrivateIP2");
        try {
            // class A Private IP
            assertEquals(IpUtil.isPrivateIP("10.168.2.1:8080"), true);
            // class B Private IP
            assertEquals(IpUtil.isPrivateIP("172.16.2.1:8080"), true);
            // class C Private IP
            assertEquals(IpUtil.isPrivateIP("192.168.2.1:80"), true);
            
            assertEquals(IpUtil.isPrivateIP("8.8.8.8:2222"), false);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }
    
    /**
     * Test of IPv4ToDecimal method, of class IpUtil.
     */
    @Test
    public void testIPv4ToDecimal() {
        try {
            System.out.println("IPv4ToDecimal");
            String raw_ip = "10.1.1.100";
            long result = IpUtil.IPv4ToDecimal(raw_ip, ByteOrder.LITTLE_ENDIAN);
            assertEquals(1677787402L, result);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    /**
     * Test of decimalToIPv4 method, of class IpUtil.
     */
    @Test
    public void testDecimalToIPv4() {
        System.out.println("decimalToIPv4");
        String enc_ip = "1677787402";
        String result = IpUtil.decimalToIPv4(Long.parseLong(enc_ip), ByteOrder.LITTLE_ENDIAN);
        assertEquals("10.1.1.100", result);
    }

    /**
     * Test of hexToIPv4 method, of class IpUtil.
     */
    @Test
    public void testHexToIPv4() {
        System.out.println("hexToIPv4");
        String enc_ip = "c0000201";
        String result = IpUtil.hexToIPv4(enc_ip, ByteOrder.BIG_ENDIAN);
        assertEquals("192.0.2.1", result);            
    }

    /**
     * Test of hexToIPv6 method, of class IpUtil.
     */
    @Test
    public void testHexToIPv6() {
        System.out.println("hexToIPv6");
        String enc_ip = "20010112000000000000000000000030";
        String result = IpUtil.hexToIPv6(enc_ip);
        assertEquals("[2001:0112:0000:0000:0000:0000:0000:0030]", result);            
    }

    /**
     * Test of decimalToPort method, of class IpUtil.
     */
    @Test
    public void testDecimalToPort() {
        System.out.println("decimalToPort");
        int enc_port = 36895;
        int result = IpUtil.decimalToPort(enc_port, ByteOrder.LITTLE_ENDIAN);
        assertEquals(8080, result);
    }
    
}
