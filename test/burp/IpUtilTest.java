/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.text.ParseException;
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
        System.out.println("IPv4ToDecimal");
    }

    /**
     * Test of decimalToIPv4 method, of class IpUtil.
     */
    @Test
    public void testDecimalToIPv4() {
        System.out.println("decimalToIPv4");
    }

    /**
     * Test of hexToIPv4 method, of class IpUtil.
     */
    @Test
    public void testHexToIPv4() {
        System.out.println("hexToIPv4");
    }

    /**
     * Test of hexToIPv6 method, of class IpUtil.
     */
    @Test
    public void testHexToIPv6() {
        System.out.println("hexToIPv6");
    }

    /**
     * Test of decimalToPort method, of class IpUtil.
     */
    @Test
    public void testDecimalToPort() {
        System.out.println("decimalToPort");
    }
    
}
