package com.isecpartners.samlpummel;

import javax.swing.JPanel;
import java.awt.Frame;
import java.awt.BorderLayout;
import javax.swing.JDialog;
import javax.swing.JTextArea;
import javax.swing.JRadioButton;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.GridLayout;
import java.awt.Dimension;

import javax.swing.JFrame;
import javax.swing.JInternalFrame;
import javax.swing.BoxLayout;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JTextPane;

import java.awt.CardLayout;
import java.awt.Label;
import java.awt.geom.Dimension2D;

import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;

public class PummelFrame extends JFrame {

	private JPanel mainContentPane, bottomButtonPanel, subLayoutPanel, topLayoutPanel, bottomLayoutPanel;

	private JTextPane signatureTextPane = null;

	private JButton submitButton, cancelButton, previewButton;

	private JLabel attackLabel, optionsLabel, assertionLabel;

	private JComboBox attackMethodComboBox = null;

	private JTextField optionsTextField = null;

	private byte[] _payload = new  byte[] {};

	private JScrollPane signatureScrollPane = null;

	private volatile Boolean _completed = Boolean.FALSE;  //  @jve:decl-index=0:

	/**
	 * @param owner
	 */
	public PummelFrame(byte[] payload) {
		super();
		_payload = payload;
		initialize();
		updateAttackMethodComboBox();
		
	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		this.setContentPane(getMainContentPane());
		this.setSize(800, 800);
		this.setTitle("SAML Pummel                  by Brad Hill (brad@isecpartners.com)");
		
		
	}

	/**
	 * This method initializes jContentPane
	 * 
	 * @return javax.swing.JPanel
	 */
	private JPanel getMainContentPane() {
		if (mainContentPane == null) {
			assertionLabel = new JLabel();
			assertionLabel.setText("Decoded SAML Assertion:");
			mainContentPane = new JPanel();
			mainContentPane.setLayout(new BoxLayout(getMainContentPane(), BoxLayout.Y_AXIS));
			mainContentPane.add(assertionLabel, null);
			mainContentPane.add(getSignatureScrollPane(), null);
			mainContentPane.add(getSubLayoutPanel(), null);
			mainContentPane.add(getBottomButtonPanel(), null);
			
		}
		return mainContentPane;
	}

	/**
	 * This method initializes jTextAreaDecodedSig	
	 * 	
	 * @return javax.swing.JTextArea	
	 */
	private JTextPane getSignatureTextPane() {
		if (signatureTextPane == null) {
			signatureTextPane = new JTextPane();
			
			signatureTextPane.setEditable(false);
			signatureTextPane.setMaximumSize(signatureTextPane.getSize());
			signatureTextPane.setAutoscrolls(true);
			signatureTextPane.setText(new String(_payload));	
			signatureTextPane.setMargin(new Insets(5,5,5,5));
		}
		
		return signatureTextPane;
	}

	
	/**
	 * This method initializes jPanel	
	 * 	
	 * @return javax.swing.JPanel	
	 */
	private JPanel getBottomButtonPanel() {
		if (bottomButtonPanel == null) {
			bottomButtonPanel = new JPanel();
			bottomButtonPanel.setLayout(new FlowLayout());
			bottomButtonPanel.add(getPreviewButton(), null);
			bottomButtonPanel.add(getSubmitButton(), null);
			bottomButtonPanel.add(getCancelButton(), null);
		}
		return bottomButtonPanel;
	}

	/**
	 * This method initializes jButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getSubmitButton() {
		if (submitButton == null) {
			submitButton = new JButton();
			submitButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent e) {
					 _payload = getNewBytes(); 
					 _completed = Boolean.TRUE;
				      
				}
			});
			submitButton.setText("Submit Attack");
		}
		return submitButton;
	}

	/**
	 * This method initializes jButton1	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getCancelButton() {
		if (cancelButton == null) {
			cancelButton = new JButton();
			cancelButton.setText("Submit Unchanged");
			cancelButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent e) {
					 _completed = Boolean.TRUE;
				}
			});
		}
		return cancelButton;
	}

	/**
	 * This method initializes jPanel1	
	 * 	
	 * @return javax.swing.JPanel	
	 */
	private JPanel getSubLayoutPanel() {
		if (subLayoutPanel == null) {
			subLayoutPanel = new JPanel();
			subLayoutPanel.setLayout(new BoxLayout(getSubLayoutPanel(), BoxLayout.Y_AXIS));
			subLayoutPanel.add(getTopLayoutPanel(), null);
			subLayoutPanel.add(getBottomLayoutPanel(), null);
			
		}
		return subLayoutPanel;
	}

	/**
	 * This method initializes jPanel2	
	 * 	
	 * @return javax.swing.JPanel	
	 */
	private JPanel getTopLayoutPanel() {
		if (topLayoutPanel == null) {
			attackLabel = new JLabel();
			attackLabel.setText(" Inject: ");
			topLayoutPanel = new JPanel();
			topLayoutPanel.setSize(800, 100);
			topLayoutPanel.setLayout(new BoxLayout(getTopLayoutPanel(), BoxLayout.X_AXIS));
			topLayoutPanel.add(attackLabel, null);
			topLayoutPanel.add(getAttackMethodComboBox(), null);
		}
		return topLayoutPanel;
	}

	/**
	 * This method initializes bottomLayoutPanel	
	 * 	
	 * @return javax.swing.JPanel	
	 */
	private JPanel getBottomLayoutPanel() {
		if (bottomLayoutPanel == null) {
			optionsLabel = new JLabel();
			optionsLabel.setText("Options:");
			bottomLayoutPanel = new JPanel();
			bottomLayoutPanel.setLayout(new BoxLayout(getBottomLayoutPanel(), BoxLayout.X_AXIS));
			bottomLayoutPanel.setSize(800,150);
			bottomLayoutPanel.add(optionsLabel, null);
			bottomLayoutPanel.add(getOptionsTextField(), null);
		}
		return bottomLayoutPanel;
	}

	/**
	 * This method initializes attackMethodComboBox	
	 * 	
	 * @return javax.swing.JComboBox	
	 */
	private JComboBox getAttackMethodComboBox() {
		if (attackMethodComboBox == null) {
			attackMethodComboBox = new JComboBox(SamlPummel.ATTACK_METHODS);	
			
			attackMethodComboBox.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent e) {
					updateAttackMethodComboBox();
				}
			});
		}	
		return attackMethodComboBox;
	}
	
	private void updateAttackMethodComboBox()
	{
		int index = attackMethodComboBox.getSelectedIndex();
		optionsLabel.setText(" " + SamlPummel.ATTACK_METHODS_TEXT[index] + ": ");
		optionsTextField.setText(SamlPummel.ATTACK_METHODS_TEXT_DEFAULT[index]);
	}
	

	/**
	 * This method initializes optionsTextField	
	 * 	
	 * @return javax.swing.JTextField	
	 */
	private JTextField getOptionsTextField() {
		if (optionsTextField == null) {
			optionsTextField = new JTextField();
			optionsTextField.setText("Attack Parameters");
		}
		return optionsTextField;
	}

	/**
	 * This method initializes jScrollPane	
	 * 	
	 * @return javax.swing.JScrollPane	
	 */
	private JScrollPane getSignatureScrollPane() {
		if (signatureScrollPane == null) {
			signatureScrollPane = new JScrollPane();
			signatureScrollPane.setViewportView(getSignatureTextPane());
		}
		return signatureScrollPane;
	}

	public byte[] getNewPayload() throws InterruptedException {
		
		// XXX  This is a horrible hack.
		// Tried using standard wait & notify pattern
		// with synchronization, but kept getting an IllegalMonitorStateException
		// the thread notifying wasn't holding the lock, even though the notify
		// was in the synchronized block.  Single step debugging gave me no
		// enlightnment.  Some weirdness with Swing I don't have time to 
		// understand right now.   A 100ms poll on a volatile variable should
		// be responsive enough without burning to omuch CPU.  
		
		while(_completed.equals(Boolean.FALSE)) {
				Thread.currentThread().sleep(100);
			}
		
		
		this.dispose();
		
		return _payload;
	}

	/**
	 * This method initializes previewButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getPreviewButton() {
		if (previewButton == null) {
			previewButton = new JButton();
			previewButton.setText("Preview");
			previewButton.addActionListener(new java.awt.event.ActionListener() {
				public void actionPerformed(java.awt.event.ActionEvent e) {
					
				    signatureTextPane.setText(new String(getNewBytes()));
				

				}
			});
		}
		return previewButton;
	}

	private byte[] getNewBytes() {
		// TODO Auto-generated method stub
		return SamlPummel.dispatchAttack((String)attackMethodComboBox.getSelectedItem(),
												optionsTextField.getText()
												,_payload);
		
	}
}
