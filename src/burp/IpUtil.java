/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.nio.ByteOrder;
import java.text.ParseException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class IpUtil {

    private final static Pattern IPv4_ADDR = Pattern.compile("([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})");
    private final static Pattern IPv4_HEX = Pattern.compile("([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})");
    private final static Pattern IPv6_HEX = Pattern.compile("([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})");
    private final static long CLASS_A_MASK = 0xFF000000L;
    private final static long CLASS_A_NET = 0x0A000000L; // 10.0.0.0/8
    private final static long CLASS_B_MASK = 0xFFF00000L;
    private final static long CLASS_B_NET = 0xAC100000L; // 172.16.0.0/12
    private final static long CLASS_C_MASK = 0xFFFF0000L;
    private final static long CLASS_C_NET = 0xC0A80000L; // 192.168.0.0/16

    public static boolean isPrivateIP(String ip_addr) throws ParseException {
        // portを分離
        String ip[] = ip_addr.split(":", 2);
        long ip_decimal = IPv4ToDecimal(ip[0], ByteOrder.BIG_ENDIAN);
        if (((ip_decimal & CLASS_A_MASK) == CLASS_A_NET)
                || ((ip_decimal & CLASS_B_MASK) == CLASS_B_NET)
                || ((ip_decimal & CLASS_C_MASK) == CLASS_C_NET)) {
            return true;
        }
        return false;
    }

    public static long IPv4ToDecimal(String ip_addr, ByteOrder order) throws ParseException {
        Matcher m = IPv4_ADDR.matcher(ip_addr);
        if (m.matches()) {
            for (int i = 1; i <= 4; i++) {
                if (!(0 <= Integer.parseInt(m.group(i)) && Integer.parseInt(m.group(i)) <= 255)) {
                    throw new ParseException("IPv4 format octet Error:", i);
                }
            }
            if (order.equals(ByteOrder.BIG_ENDIAN)) {
                String ip_hex = String.format("%02x%02x%02x%02x", Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)));
                return Long.parseLong(ip_hex, 16);
            } else {
                String ip_hex = String.format("%02x%02x%02x%02x", Integer.parseInt(m.group(4)), Integer.parseInt(m.group(3)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(1)));
                return Long.parseLong(ip_hex, 16);
            }
        }
        return -1;
    }

    public static String decimalToIPv4(long ip_decimal, ByteOrder order) {
        return hexToIPv4(String.format("%08x", ip_decimal), order);
    }

    public static String hexToIPv4(String ip_hex, ByteOrder order) {
        String ipv4 = null;
        Matcher m = IPv4_HEX.matcher(ip_hex);
        if (m.matches()) {
            if (order.equals(ByteOrder.BIG_ENDIAN)) {
                ipv4 = String.format("%d.%d.%d.%d",
                        Integer.parseInt(m.group(1), 16),
                        Integer.parseInt(m.group(2), 16),
                        Integer.parseInt(m.group(3), 16),
                        Integer.parseInt(m.group(4), 16));
            } else {
                ipv4 = String.format("%d.%d.%d.%d",
                        Integer.parseInt(m.group(4), 16),
                        Integer.parseInt(m.group(3), 16),
                        Integer.parseInt(m.group(2), 16),
                        Integer.parseInt(m.group(1), 16));
            }
        }
        return ipv4;
    }

    public static String hexToIPv6(String ip_hex) {
        String ipv6 = null;
        Matcher m = IPv6_HEX.matcher(ip_hex);
        if (m.matches()) {
            return String.format("[%s:%s:%s:%s:%s:%s:%s:%s]", m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7), m.group(8));
        }
        return ipv6;
    }

    public static int decimalToPort(int port_decimal, ByteOrder order) {
        String port_hex = String.format("%04x", port_decimal);
        if (order.equals(ByteOrder.BIG_ENDIAN)) {
            return Integer.parseInt(String.format("%s%s", port_hex.substring(0, 2), port_hex.substring(2, 4)), 16);
        } else {
            return Integer.parseInt(String.format("%s%s", port_hex.substring(2, 4), port_hex.substring(0, 2)), 16);
        }
    }

}
