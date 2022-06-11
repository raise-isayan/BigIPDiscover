package passive.common;

import extension.helpers.HttpMessage;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 *
 * @author isayan
 */
public final class JMultilineLabel extends JPanel {

    public JMultilineLabel() {
        this("");
    }

    public JMultilineLabel(String label) {
        setText(label);
    }

    private final List<JLabel> labels = new ArrayList();


    public void setText(String messages) {
        removeAll();
        this.labels.clear();
        String[] lines = messages.split("\n");
        setLayout(new GridLayout(lines.length, 1));
        for (String line : lines) {
            JLabel label = new JLabel(line);
            this.labels.add(label);
            if (this.isListed()) {
                label.setIcon(new javax.swing.ImageIcon(getClass().getResource("/passive/signature/resources/bullet_black.png")));
            }
            add(label);
        }
        repaint();
    }

    private boolean listed = false;

    /**
     * @return the listed
     */
    public boolean isListed() {
        return listed;
    }

    /**
     * @param listed the listed to set
     */
    public void setListed(boolean listed) {
        this.listed = listed;
        for (JLabel label : this.labels) {
            if (this.isListed()) {
                label.setIcon(new javax.swing.ImageIcon(getClass().getResource("/passive/signature/resources/bullet_black.png")));
            }
            else {
                label.setIcon(null);
            }
        }
    }


    public static void main(String args[]) {
        JMultilineLabel label = new JMultilineLabel("First\nSecont\nThird:");
        final JTextField text = new JTextField(20);
        JButton b = new JButton("popup");
        b.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                label.setText("");
            }
        });
        JPanel p = new JPanel();
        p.add(label);
        p.add(text);
        p.add(b);
        final JFrame f = new JFrame();
        f.getContentPane().add(p);
        f.pack();
        f.setVisible(true);
    }

}
