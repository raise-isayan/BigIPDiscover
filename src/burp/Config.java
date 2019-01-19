package burp;

import extend.util.IniProp;
import extend.util.Util;
import extend.view.base.MatchItem;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.util.EnumSet;
import javax.xml.bind.JAXB;

/**
 *
 * @author isayan
 */
public final class Config {

    private Config() {
    }

    public static void saveToXML(File fi, OptionProperty option) throws IOException {
        JAXB.marshal(option, fi);
    }

    public static void loadFromXML(File fi, OptionProperty option) throws IOException {
        OptionProperty property = JAXB.unmarshal(fi, OptionProperty.class);
        option.setProperty(property);
    }

    /**
     * Propertyファイルの読み込み
     *
     * @param content コンテンツ内容
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void loadFromXml(String content, OptionProperty option) throws IOException {
        OptionProperty property = JAXB.unmarshal(content, OptionProperty.class);
        option.setProperty(property);
    }

    public static String saveToXML(OptionProperty option) throws IOException {
        StringWriter writer = new StringWriter();
        JAXB.marshal(option, writer);
        return writer.toString();
    }

    /**
     * Propertyファイルの読み込み
     *
     * @param fi ファイル名
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void loadFromXml(File fi, IOptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        prop.loadFromXML(fi);
        loadFromXml(prop, option);
    }

    /**
     * Propertyファイルの読み込み
     *
     * @param content コンテンツ内容
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void loadFromXml(String content, IOptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        prop.loadFromXML(content);
        loadFromXml(prop, option);
    }

    protected static void loadFromXml(IniProp prop, IOptionProperty option) throws IOException {
        ScanProperty scan = option.getScan();
        scan.setScanRequest(prop.readEntryBool("scan", "request", true));
        scan.setScanResponse(prop.readEntryBool("scan", "response", true));

        String notyfys = prop.readEntry("scan", "notify", "[]");
        EnumSet<MatchItem.NotifyType> notyfyset = EnumSet.noneOf(MatchItem.NotifyType.class);
        notyfyset.addAll(MatchItem.NotifyType.enumSetValueOf(notyfys));
        scan.setNotifyTypes(notyfyset);

        if (scan.getNotifyTypes().contains(MatchItem.NotifyType.ITEM_HIGHLIGHT)) {
            String highlightColor = prop.readEntry("scan", "highlightColor", "");
            scan.setHighlightColor(MatchItem.HighlightColor.valueOf(highlightColor));
        }

        // Detection
        scan.setDetectionPrivateIP(prop.readEntryBool("detection", "privateIP", true));

    }

    /**
     * Propertyファイルの書き込み
     *
     * @param fo ファイル名
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void saveToXML(File fo, IOptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        saveToXML(prop, option);
        prop.storeToXML(fo, "Temporary Properties", "UTF-8");
    }

    public static String saveToXML(IOptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        saveToXML(prop, option);
        return prop.storeToXML("Temporary Properties", "UTF-8");
    }

    protected static void saveToXML(IniProp prop, IOptionProperty option) throws IOException {
        ScanProperty scan = option.getScan();

        // Scan
        prop.writeEntryBool("scan", "request", scan.getScanRequest());
        prop.writeEntryBool("scan", "response", scan.getScanResponse());

        EnumSet<MatchItem.NotifyType> notifys = scan.getNotifyTypes();
        prop.writeEntry("scan", "notify", Util.enumSetToString(notifys));
        if (scan.getNotifyTypes().contains(MatchItem.NotifyType.ITEM_HIGHLIGHT)) {
            prop.writeEntry("scan", "highlightColor", scan.getHighlightColor().name());
        }

        // Detection
        prop.writeEntryBool("detection", "privateIP", scan.isDetectionPrivateIP());

    }

}
