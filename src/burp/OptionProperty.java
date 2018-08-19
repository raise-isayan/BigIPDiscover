/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

/**
 *
 * @author isayan
 */
public interface OptionProperty {
    public final static String SCAN_PROPERTY = "ScanPropery";

    public ScanProperty getScan();

    public void setScan(ScanProperty scan);

}
