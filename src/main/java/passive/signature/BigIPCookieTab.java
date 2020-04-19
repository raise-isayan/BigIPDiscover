package passive.signature;

import burp.BurpExtender;
import passive.IOptionProperty;
import burp.ITab;
import extend.util.IpUtil;
import extend.util.SwingUtil;
import extend.util.Util;
import extend.view.base.MatchItem;
import java.awt.Component;
import java.awt.event.ComponentEvent;
import java.text.ParseException;
import java.util.EnumSet;
import java.util.MissingResourceException;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 *
 * @author isayan
 */
public class BigIPCookieTab extends javax.swing.JPanel implements ITab {

    private final String PRIVATE_IP_INFO = "<html><ul><li>PrivateIP: %s</li><li>LinkLocalIP: %s</li></ul></html>";
    
    /**
     * Creates new form BigIpDecryptTab
     */
    public BigIPCookieTab() {
        initComponents();
        customizeComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        tabbetOption = new javax.swing.JTabbedPane();
        pnlOptions = new javax.swing.JPanel();
        pnlScanHeader = new javax.swing.JPanel();
        chkResponse = new javax.swing.JCheckBox();
        chkRequest = new javax.swing.JCheckBox();
        pnlFreeScan = new javax.swing.JPanel();
        chk_Comment = new javax.swing.JCheckBox();
        cmbHighlightColor = new javax.swing.JComboBox();
        chkItem_highlight = new javax.swing.JCheckBox();
        pnlDetectionOption = new javax.swing.JPanel();
        chkPrivateIP = new javax.swing.JCheckBox();
        jLabel1 = new javax.swing.JLabel();
        pnlDecrypt = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtDecrypt = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        txtEncrypt = new javax.swing.JTextArea();
        btnDecrypt = new javax.swing.JButton();
        lblDecryptInfo = new javax.swing.JLabel();

        setLayout(new java.awt.BorderLayout());

        pnlScanHeader.setBorder(javax.swing.BorderFactory.createTitledBorder("Scan Header"));

        chkResponse.setSelected(true);
        chkResponse.setText("Response Set-Cookie");
        chkResponse.setEnabled(false);
        chkResponse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chkResponseActionPerformed(evt);
            }
        });

        chkRequest.setText("Request Cookie");
        chkRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chkRequestActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlScanHeaderLayout = new javax.swing.GroupLayout(pnlScanHeader);
        pnlScanHeader.setLayout(pnlScanHeaderLayout);
        pnlScanHeaderLayout.setHorizontalGroup(
            pnlScanHeaderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlScanHeaderLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlScanHeaderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(chkResponse)
                    .addComponent(chkRequest))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        pnlScanHeaderLayout.setVerticalGroup(
            pnlScanHeaderLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlScanHeaderLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(chkResponse)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(chkRequest)
                .addContainerGap(28, Short.MAX_VALUE))
        );

        pnlFreeScan.setBorder(javax.swing.BorderFactory.createTitledBorder("Community edition scan option"));

        chk_Comment.setText("comment");
        chk_Comment.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chk_CommentActionPerformed(evt);
            }
        });

        cmbHighlightColor.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray" }));
        cmbHighlightColor.setEnabled(false);
        cmbHighlightColor.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmbHighlightColorActionPerformed(evt);
            }
        });

        chkItem_highlight.setText("item highlight");
        chkItem_highlight.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chkItem_highlightActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlFreeScanLayout = new javax.swing.GroupLayout(pnlFreeScan);
        pnlFreeScan.setLayout(pnlFreeScanLayout);
        pnlFreeScanLayout.setHorizontalGroup(
            pnlFreeScanLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlFreeScanLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlFreeScanLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlFreeScanLayout.createSequentialGroup()
                        .addGap(24, 24, 24)
                        .addComponent(cmbHighlightColor, javax.swing.GroupLayout.PREFERRED_SIZE, 341, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(chkItem_highlight)
                    .addComponent(chk_Comment))
                .addContainerGap(23, Short.MAX_VALUE))
        );
        pnlFreeScanLayout.setVerticalGroup(
            pnlFreeScanLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlFreeScanLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(chkItem_highlight)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cmbHighlightColor, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(chk_Comment)
                .addContainerGap(130, Short.MAX_VALUE))
        );

        pnlDetectionOption.setBorder(javax.swing.BorderFactory.createTitledBorder("Detection Option"));

        chkPrivateIP.setText("Private IP Only");
        chkPrivateIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chkPrivateIPActionPerformed(evt);
            }
        });

        jLabel1.setText("<html><ul><li>PrivateIP: Severity: Low</li><li>OtherIP: Severity: Info</li></ul> ");

        javax.swing.GroupLayout pnlDetectionOptionLayout = new javax.swing.GroupLayout(pnlDetectionOption);
        pnlDetectionOption.setLayout(pnlDetectionOptionLayout);
        pnlDetectionOptionLayout.setHorizontalGroup(
            pnlDetectionOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlDetectionOptionLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlDetectionOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(chkPrivateIP, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 247, Short.MAX_VALUE))
                .addContainerGap())
        );
        pnlDetectionOptionLayout.setVerticalGroup(
            pnlDetectionOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlDetectionOptionLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(chkPrivateIP)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 42, Short.MAX_VALUE)
                .addContainerGap())
        );

        javax.swing.GroupLayout pnlOptionsLayout = new javax.swing.GroupLayout(pnlOptions);
        pnlOptions.setLayout(pnlOptionsLayout);
        pnlOptionsLayout.setHorizontalGroup(
            pnlOptionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlOptionsLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlOptionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(pnlScanHeader, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(pnlDetectionOption, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(pnlFreeScan, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        pnlOptionsLayout.setVerticalGroup(
            pnlOptionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlOptionsLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlOptionsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(pnlFreeScan, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(pnlOptionsLayout.createSequentialGroup()
                        .addComponent(pnlScanHeader, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(pnlDetectionOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(105, Short.MAX_VALUE))
        );

        tabbetOption.addTab("Options", pnlOptions);

        txtDecrypt.setEditable(false);
        txtDecrypt.setColumns(20);
        txtDecrypt.setRows(5);
        jScrollPane1.setViewportView(txtDecrypt);

        txtEncrypt.setColumns(20);
        txtEncrypt.setRows(5);
        jScrollPane2.setViewportView(txtEncrypt);

        btnDecrypt.setText("Decrypt");
        btnDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecryptActionPerformed(evt);
            }
        });

        lblDecryptInfo.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        lblDecryptInfo.setVerticalAlignment(javax.swing.SwingConstants.TOP);
        lblDecryptInfo.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        lblDecryptInfo.setVerticalTextPosition(javax.swing.SwingConstants.TOP);

        javax.swing.GroupLayout pnlDecryptLayout = new javax.swing.GroupLayout(pnlDecrypt);
        pnlDecrypt.setLayout(pnlDecryptLayout);
        pnlDecryptLayout.setHorizontalGroup(
            pnlDecryptLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlDecryptLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlDecryptLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 530, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(pnlDecryptLayout.createSequentialGroup()
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 530, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(pnlDecryptLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(pnlDecryptLayout.createSequentialGroup()
                                .addComponent(btnDecrypt)
                                .addGap(0, 85, Short.MAX_VALUE))
                            .addComponent(lblDecryptInfo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                .addContainerGap())
        );
        pnlDecryptLayout.setVerticalGroup(
            pnlDecryptLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlDecryptLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlDecryptLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(pnlDecryptLayout.createSequentialGroup()
                        .addComponent(btnDecrypt)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lblDecryptInfo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(142, Short.MAX_VALUE))
        );

        tabbetOption.addTab("Decrypt", pnlDecrypt);

        add(tabbetOption, java.awt.BorderLayout.PAGE_START);
    }// </editor-fold>//GEN-END:initComponents

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("burp/resources/release");
    
    private boolean isFreeSupport() {
        boolean freeSupport = false;
        try {
            freeSupport = Util.parseBooleanDefault(BUNDLE.getString("freeSupport"), false);        
        } catch (MissingResourceException ex) {        
        }
        return freeSupport;
    }
    
    private void customizeComponents() {

        this.cmbHighlightColor.setModel(
            new DefaultComboBoxModel(
                new MatchItem.HighlightColor[]{MatchItem.HighlightColor.RED, MatchItem.HighlightColor.ORANGE,
                    MatchItem.HighlightColor.YELLOW, MatchItem.HighlightColor.GREEN, MatchItem.HighlightColor.CYAN,
                    MatchItem.HighlightColor.BLUE, MatchItem.HighlightColor.PINK, MatchItem.HighlightColor.MAGENTA,
                    MatchItem.HighlightColor.GRAY}));

        this.cmbHighlightColor.setEnabled(false);
        this.cmbHighlightColor.setRenderer(new DefaultListCellRenderer() {

            @Override
            public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                JLabel l = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                MatchItem.HighlightColor hc = (MatchItem.HighlightColor) value;
                if (hc != null) {
                    l.setIcon(hc.toIcon());
                    l.setIconTextGap(2);
                }
                return l;
            }
        });
        this.txtEncrypt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                lblDecryptInfo.setText("");
                txtDecrypt.setText("");
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                lblDecryptInfo.setText("");
                txtDecrypt.setText("");
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                lblDecryptInfo.setText("");
                txtDecrypt.setText("");
            }        
        });

        this.pnlFreeScan.setVisible(isFreeSupport());        
        // FreeVersion only
        this.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                if (isFreeSupport()) {
                    boolean isProfessional = BurpExtender.getInstance().getBurpVersion().isProfessional();
                    pnlFreeScan.setVisible(isFreeSupport());        
                    SwingUtil.setContainerEnable(pnlFreeScan, !isProfessional);            
                }
            }
        });
        
    }

    private void btnDecryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDecryptActionPerformed
        this.txtDecrypt.setText("");        
        this.lblDecryptInfo.setText("");
        String value = BigIPCookie.decrypt(this.txtEncrypt.getText());
        if (value != null) {
            try {
                this.lblDecryptInfo.setText(String.format(PRIVATE_IP_INFO, IpUtil.isPrivateIP(value), IpUtil.isLinkLocalIP(value)));    
                this.txtDecrypt.setText(value);
            } catch (ParseException ex) {
            }
        }
    }//GEN-LAST:event_btnDecryptActionPerformed
    
    private void cmbHighlightColorActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmbHighlightColorActionPerformed
        this.firePropertyChange(IOptionProperty.BIGIP_COOKIE_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_cmbHighlightColorActionPerformed

    private void chkPrivateIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkPrivateIPActionPerformed
        this.firePropertyChange(IOptionProperty.BIGIP_COOKIE_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_chkPrivateIPActionPerformed

    private void chkRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkRequestActionPerformed
        this.firePropertyChange(IOptionProperty.BIGIP_COOKIE_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_chkRequestActionPerformed

    private void chkResponseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkResponseActionPerformed
        this.firePropertyChange(IOptionProperty.BIGIP_COOKIE_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_chkResponseActionPerformed

    private void chkItem_highlightActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkItem_highlightActionPerformed
        this.firePropertyChange(IOptionProperty.BIGIP_COOKIE_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_chkItem_highlightActionPerformed

    private void chk_CommentActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chk_CommentActionPerformed
        this.firePropertyChange(IOptionProperty.BIGIP_COOKIE_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_chk_CommentActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnDecrypt;
    private javax.swing.JCheckBox chkItem_highlight;
    private javax.swing.JCheckBox chkPrivateIP;
    private javax.swing.JCheckBox chkRequest;
    private javax.swing.JCheckBox chkResponse;
    private javax.swing.JCheckBox chk_Comment;
    private javax.swing.JComboBox cmbHighlightColor;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JLabel lblDecryptInfo;
    private javax.swing.JPanel pnlDecrypt;
    private javax.swing.JPanel pnlDetectionOption;
    private javax.swing.JPanel pnlFreeScan;
    private javax.swing.JPanel pnlOptions;
    private javax.swing.JPanel pnlScanHeader;
    private javax.swing.JTabbedPane tabbetOption;
    private javax.swing.JTextArea txtDecrypt;
    private javax.swing.JTextArea txtEncrypt;
    // End of variables declaration//GEN-END:variables

    @Override
    public String getTabCaption() {
        return "BIG-IP Cookie";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    public void setProperty(BigIPCookieProperty property) {
        this.chkRequest.setSelected(property.getScanRequest());
        this.chkResponse.setSelected(property.getScanResponse());

        EnumSet<MatchItem.NotifyType> notifyTypes = property.getNotifyTypes();
        this.chkItem_highlight.setSelected(notifyTypes.contains(MatchItem.NotifyType.ITEM_HIGHLIGHT));
        this.chk_Comment.setSelected(notifyTypes.contains(MatchItem.NotifyType.COMMENT));
        this.cmbHighlightColor.setSelectedItem(property.getHighlightColor());

        this.chkPrivateIP.setSelected(property.isDetectionPrivateIP());
    }

    public BigIPCookieProperty getProperty() {
        BigIPCookieProperty property = new BigIPCookieProperty();
        property.setScanRequest(this.chkRequest.isSelected());
        property.setScanResponse(this.chkResponse.isSelected());

        EnumSet<MatchItem.NotifyType> notifyTypes = EnumSet.noneOf(MatchItem.NotifyType.class);
        if (this.chkItem_highlight.isSelected()) {
            notifyTypes.add(MatchItem.NotifyType.ITEM_HIGHLIGHT);
        }
        if (this.chk_Comment.isSelected()) {
            notifyTypes.add(MatchItem.NotifyType.COMMENT);
        }
        property.setNotifyTypes(notifyTypes);
        if (property.getNotifyTypes().contains(MatchItem.NotifyType.ITEM_HIGHLIGHT)) {
            property.setHighlightColor((MatchItem.HighlightColor) this.cmbHighlightColor.getSelectedItem());
        }
        property.setDetectionPrivateIP(this.chkPrivateIP.isSelected());

        return property;
    }

}
