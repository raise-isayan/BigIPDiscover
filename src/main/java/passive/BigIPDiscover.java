package passive;

import burp.BurpExtender;
import extension.helpers.IpUtil;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import passive.signature.BigIPCookie;

/**
 *
 * @author isayan
 */
public class BigIPDiscover {
    private final static Logger logger = Logger.getLogger(BigIPDiscover.class.getName());

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            String encrypt_value = null;
            for (int i = 0; i < args.length; i += 2) {
                String[] param = Arrays.copyOfRange(args, i, args.length);
                if (param.length > 1) {
                    if ("-d".equals(param[0])) {
                        encrypt_value = param[1];
                    }
                } else if (param.length > 0) {
                    if ("-v".equals(param[0])) {
                        System.out.print("Version: " + getVersion());
                        System.exit(0);
                    }
                    if ("-h".equals(param[0])) {
                        usage();
                        System.exit(0);
                    }

                } else {
                    throw new IllegalArgumentException("argment err:" + String.join(" ", param));
                }
            }

            // 必須チェック
            if (encrypt_value == null) {
                System.out.println("-d argument err ");
                usage();
                return;
            }

            String bigIPaddr = BigIPCookie.decrypt(encrypt_value);
            System.out.println("IP addres: " + bigIPaddr);
            System.out.println("PrivateIP: " + IpUtil.isPrivateIP(bigIPaddr));
            System.out.println("LinkLocalIP: " + IpUtil.isLinkLocalIP(bigIPaddr));

        } catch (Exception ex) {
            String errmsg = String.format("%s: %s", ex.getClass().getName(), ex.getMessage());
            System.out.println(errmsg);
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            usage();
        }
    }

    private static void usage() {
        final String projname = BUNDLE.getString("projname");
        System.out.println(String.format("Usage: java -jar %s.jar -d <encrypt>", projname));
        System.out.println(String.format("   ex: java -jar %s.jar -d BIGipServer16122=1677787402.36895.0000", projname));
    }

    public static String getProjectName() {
        return BUNDLE.getString("projname");
    }

    public static String getVersion() {
        return BUNDLE.getString("version");
    }

}
