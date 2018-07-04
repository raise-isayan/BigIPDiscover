/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import extend.util.IniProp;
import extend.util.Util;
import extend.view.base.MatchItem;
import java.io.File;
import java.io.IOException;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public final class Config {

    private Config() {
    }

    /**
     * Propertyファイルの読み込み
     *
     * @param fi ファイル名
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void loadFromXml(File fi, OptionProperty option) throws IOException {
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
    public static void loadFromXml(String content, OptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        prop.loadFromXML(content);
        loadFromXml(prop, option);
    }

    protected static void loadFromXml(IniProp prop, OptionProperty option) throws IOException {
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
        scan.setDetectionPrivateIP(prop.readEntryBool("detection", "detectionPrivateIP", true));
        
    }

    /**
     * Propertyファイルの書き込み
     *
     * @param fo ファイル名
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void saveToXML(File fo, OptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        saveToXML(prop, option);
        prop.storeToXML(fo, "Temporary Properties", "UTF-8");
    }

    public static String saveToXML(OptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        saveToXML(prop, option);
        return prop.storeToXML("Temporary Properties", "UTF-8");
    }

    protected static void saveToXML(IniProp prop, OptionProperty option) throws IOException {
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
