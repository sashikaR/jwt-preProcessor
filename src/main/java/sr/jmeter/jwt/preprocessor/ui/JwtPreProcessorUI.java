package sr.jmeter.jwt.preprocessor.ui;

import sr.jmeter.jwt.preprocessor.JwtPreProcessor;
import sr.jmeter.jwt.preprocessor.service.Algorithm;
import org.apache.jmeter.gui.util.HorizontalPanel;
import org.apache.jmeter.processor.gui.AbstractPreProcessorGui;
import org.apache.jmeter.testelement.TestElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.plaf.basic.BasicBorders;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.Map;

import static sr.jmeter.jwt.preprocessor.service.util.JwtProperties.*;
import static sr.jmeter.jwt.preprocessor.service.util.JwtUtil.filterEmptyRows;
import static sr.jmeter.jwt.preprocessor.service.util.JwtUtil.getTableData;

public class JwtPreProcessorUI extends AbstractPreProcessorGui {

    private final JTextField textField;
    private final JTextField txtFieldSecretKey = new JTextField();;
    private final JRadioButton buttonHS256 = new JRadioButton();
    private final JRadioButton buttonRS256 = new JRadioButton();
    private final JRadioButton buttonNoSigning = new JRadioButton();
    private final Object[] jTableHeader =new Object[]{"Header Attribute", "Header Value"};
    private final Object[] jTableHeaderPayload =new Object[]{"Payload Attribute", "Payload Value"};
    private final Object[] jTableHeaderClaims =new Object[]{"Claim Attribute", "Claim Value"};
    private final DefaultTableModel jHeaderTableModel = new DefaultTableModel(jTableHeader, 0);
    private final JwtPayloadJtableModel jPayloadTableModel = new JwtPayloadJtableModel(jTableHeaderPayload, 0);
    private final DefaultTableModel jClaimsTableModel = new DefaultTableModel(jTableHeaderClaims, 0);
    private final JTable jwtHeaderTable = new JTable(jHeaderTableModel);
    private final JTable jwtPayloadTable = new JTable(jPayloadTableModel);
    private final JTable jwtPayloadClaimsTable = new JTable(jClaimsTableModel);
    private final JTextField txtFieldVariableNameToUse = new JTextField();;
    private static final String preProcessorName = PRE_PROCESSOR_NAME;
    private boolean isPayloadTablePopulated = false;

    private static final Logger log = LogManager.getLogger(JwtPreProcessorUI.class);

    public JwtPreProcessorUI(){
        textField = new JTextField();
        init();
    }

    @Override
    public String getLabelResource() {
        return preProcessorName;
    }

    @Override
    public String getStaticLabel() {
        return preProcessorName;
    }


    /**
     * The createTestElement() method,
     * initialize the JwtPreProcessor Object
     * set defaults values
     * @return TestElement
     */
    @Override
    public TestElement createTestElement() {
        JwtPreProcessor preProcessor = new JwtPreProcessor();
        preProcessor.setAlgorithm(buttonNoSigning.getText()); // Set the default algorithm value
        addDefaultJwtPayloadAttributes(preProcessor); // Adding default payload attributes
        preProcessor.setVariableNameToUse("jwtString"); // Set the default variable name to save JWT
        configureTestElement(preProcessor);
        return preProcessor;
    }

    /**
     * The modifyTestElement() method, invoked when save the Jmeter Test Plan.
     * @param testElement
     */
    @Override
    public void modifyTestElement(TestElement testElement) {
        super.configureTestElement(testElement);
        if (testElement instanceof JwtPreProcessor) {
            JwtPreProcessor jwtPreProcessor = (JwtPreProcessor) testElement;
            jwtPreProcessor.setSecretKey(txtFieldSecretKey.getText());
            jwtPreProcessor.setAlgorithm(getSelectedAlgorithm());
            jwtPreProcessor.setJwtHeaderData(filterEmptyRows(getTableData(jwtHeaderTable)));
            jwtPreProcessor.setJwtPayloadData(filterEmptyRows(getTableData(jwtPayloadTable)));
            jwtPreProcessor.setJwtClaimsData(filterEmptyRows(getTableData(jwtPayloadClaimsTable)));
            jwtPreProcessor.setVariableNameToUse(txtFieldVariableNameToUse.getText());
            log.trace("Setting key value from modifyTestElement() -----> "+jwtPreProcessor.getSecretKey());
            log.trace("Setting algorithm from modifyTestElement() -----> "+jwtPreProcessor.getAlgorithm());
            log.trace("Setting Jwt Headers from jwtPreProcessor in modifyTestElement() -----> "+jwtPreProcessor.getJwtHeaderData()); // {}
            log.trace("Setting Jwt Headers from getTableData in modifyTestElement() -----> "+getTableData(jwtHeaderTable)); // {}
            log.trace("Setting Jwt Payload from jwtPreProcessor in modifyTestElement() -----> "+jwtPreProcessor.getJwtPayloadData()); // {}
            log.trace("Setting Jwt Payload from getTableData() in modifyTestElement() -----> "+getTableData(jwtPayloadTable)); // {}
            log.trace("Setting Jwt Payload Claims from getTableData() in modifyTestElement() -----> "+getTableData(jwtPayloadClaimsTable)); // {}
            log.trace("Setting variableNameToUse from modifyTestElement() -----> "+jwtPreProcessor.getVariableNameToUse());

        }
    }

    /**
     * The configure() method, invoked when Jmeter loading the test plan
     * @param testElement
     */
    @Override
    public void configure(TestElement testElement) {
        super.configure(testElement);
        if (testElement instanceof JwtPreProcessor jwtPreProcessor) {
            // set secretKey
            txtFieldSecretKey.setText(jwtPreProcessor.getSecretKey());

            // set Algorithm selection
            setSelectedAlgorithm(jwtPreProcessor.getAlgorithm());

            // Check if jwt payload table is not populated ye
            if (!isPayloadTablePopulated) {
                populateJwtPayloadTable(jwtPreProcessor);
                isPayloadTablePopulated = true; // Set the flag
            }
            // Populate the JWT Header Table
            populateJwtHeaderTable(jwtPreProcessor);
            // Populate the JWT Claims Table
            populateJwtClaimsTable(jwtPreProcessor);

            // set Jmeter Variable Name To Use
            txtFieldVariableNameToUse.setText(jwtPreProcessor.getVariableNameToUse());
            log.trace("Setting key value from configure() -----> "+jwtPreProcessor.getSecretKey());
            log.trace("Setting algorithm value from configure() -----> "+jwtPreProcessor.getAlgorithm());
            log.trace("Setting Jwt Headers from configure() -----> "+jwtPreProcessor.getJwtHeaderData());
            log.trace("Setting Jwt Payload from configure() -----> "+jwtPreProcessor.getJwtPayloadData());
            log.trace("Setting variableNameToUse from configure() -----> "+jwtPreProcessor.getVariableNameToUse());
        }
    }

    private void populateJwtHeaderTable(JwtPreProcessor jwtPreProcessor){
        DefaultTableModel headerTableModel = (DefaultTableModel) jwtHeaderTable.getModel();
        headerTableModel.setRowCount(0); // Clear existing rows
        Map<String, String> jwtHeaderData = jwtPreProcessor.getJwtHeaderData();
        for (Map.Entry<String, String> entry : jwtHeaderData.entrySet()) {
            headerTableModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }
    }

    private void populateJwtPayloadTable(JwtPreProcessor jwtPreProcessor){
        DefaultTableModel payloadTableModel = (DefaultTableModel) jwtPayloadTable.getModel();
        Map<String,String> jwtPayloadData = jwtPreProcessor.getJwtPayloadData();
        for (Map.Entry<String, String> entry : jwtPayloadData.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if( key!=null){
                payloadTableModel.addRow(new Object[]{key, value});
            }
        }
    }

    private void populateJwtClaimsTable(JwtPreProcessor jwtPreProcessor){
        DefaultTableModel claimsTableModel = (DefaultTableModel) jwtPayloadClaimsTable.getModel();
        claimsTableModel.setRowCount(0); // Clear existing rows
        Map<String, String> jwtClaimsData = jwtPreProcessor.getJwtClaimsData();
        for (Map.Entry<String, String> entry : jwtClaimsData.entrySet()) {
            claimsTableModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }
    }

    @Override
    public void clearGui() {
        super.clearGui();
        textField.setText(""); // Reset the text field value
    }

    /**
     * Initializing the plugin ui
     * Define layout
     */
    private void init()
    {
        setLayout(new BorderLayout());
        setBorder(makeBorder());
        Box box = Box.createVerticalBox();
        box.add(makeTitlePanel());
        box.add(makeSourcePanel());
        add(box,BorderLayout.NORTH);
    }


    /**
     * Defining the UI main components
     * @return Component
     */
    private Component makeSourcePanel(){
        Box box = Box.createVerticalBox();
        box.add(addAlgorithmSelection(), BorderLayout.CENTER);
        box.add(addSigningKeyTextBox(),BorderLayout.CENTER);
        box.add(addCustomJwtHeader(),BorderLayout.CENTER);
        box.add(addJwtPayload(),BorderLayout.CENTER);
        box.add(addJwtPayloadClaims(),BorderLayout.CENTER);
        box.add(addJwtVariableTextField(),BorderLayout.CENTER);
        return box;
    }

    /**
     * Define Algorithm Selection UI
     * @return Component
     */
    private Component addAlgorithmSelection(){
        // Create a JPanel for Radio Buttons
        JPanel jPanelRadioButtons= new JPanel();
        // Create a ButtonGroup to group the radio buttons
        ButtonGroup buttonGroup = new ButtonGroup();

        buttonHS256.setText(Algorithm.HS256.toString());
        buttonRS256.setText(Algorithm.RS256.toString());
        buttonNoSigning.setText(Algorithm.NO_SIGN.toString());
        // Add the radio buttons to the ButtonGroup
        buttonGroup.add(buttonHS256);
        buttonGroup.add(buttonRS256);
        buttonGroup.add(buttonNoSigning);

        // Add action listeners to capture user's selection
        buttonHS256.addActionListener(e -> {
            // Handle user's selection here
        });
        buttonRS256.addActionListener(e -> {
            // Handle user's selection here
        });
        buttonNoSigning.addActionListener(e -> {
            // Handle user's selection here
        });

        // Add the radio buttons to the preProcessorMenu
        jPanelRadioButtons.add(buttonHS256);
        jPanelRadioButtons.add(buttonRS256);
        jPanelRadioButtons.add(buttonNoSigning);

        // Set the titled border on the radio buttons panel
        jPanelRadioButtons.setBorder(getTitledBorder("Select Algorithm"));

        HorizontalPanel panelOfAlgorithmData = new HorizontalPanel();
        // Add radio buttons panel to HorizontalPanel
        panelOfAlgorithmData.add(jPanelRadioButtons);

        // Add space at the bottom of box
        add(Box.createHorizontalStrut(1000));
        return panelOfAlgorithmData;
    }

    private TitledBorder getTitledBorder(String title){
        // Create a TitledBorder for the embossed border
        TitledBorder titledBorder = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), title);
        titledBorder.setTitleFont(new Font("Arial", Font.BOLD, 12));
        return titledBorder;
    }

    private String getSelectedAlgorithm() {
        if (buttonHS256.isSelected()) {
            return buttonHS256.getText();
        } else if (buttonRS256.isSelected()) {
            return buttonRS256.getText();
        } else {
            return buttonNoSigning.getText();
        }
    }

    /**
     * Define SecretKey Text Fields in UI
     * @return Component
     */
    private void setSelectedAlgorithm(String algorithm) {
        if (algorithm.equals(buttonHS256.getText())) {
            buttonHS256.setSelected(true);
        } else if (algorithm.equals(buttonRS256.getText())) {
            buttonRS256.setSelected(true);
        } else {
            buttonNoSigning.setSelected(true);
        }
    }

    /**
     * Define SecretKey Text Fields in UI
     * @return Component
     */
    private Component addSigningKeyTextBox(){
        HorizontalPanel signingKeyPanel = new HorizontalPanel();

        // Create a vertical- jbox for Signing Key
        Box jBoxSigningKey = Box.createVerticalBox();
        // Add Signing Key-note
        JLabel textPane = new JLabel();
        textPane.setText("Add either Private Key or Symmetric Key as Secret Key. Keep empty when signing is not required.");
        // Add signing note to vertical-jbox
        jBoxSigningKey.add(textPane,BorderLayout.EAST);

        // ************** Set Secret-Key text field **************
        // Create a horizontal-jobx for label and text field - Secret Key
        Box keyTextField = Box.createHorizontalBox();
        JLabel labelSecret = new JLabel("Secret Key:");
        keyTextField.add(labelSecret);
        keyTextField.add(txtFieldSecretKey);
        // Add textField box into vertical-box
        jBoxSigningKey.add(keyTextField,BorderLayout.EAST);

        // Add the vertical-jox into HorizontalPanelBox
        signingKeyPanel.add(jBoxSigningKey);
        signingKeyPanel.setBorder(getTitledBorder("Set Signing Key"));

        return signingKeyPanel;
    }

    /**
     * Add Jwt Header Table
     * @return Component
     */
    private Component addCustomJwtHeader(){
        // Create a JPanel for Custom Header Attributes
        JPanel jPanelJwtHeader= new JPanel();

        // Set the titled border on the Custom Header Attributes panel
        jPanelJwtHeader.setBorder(getTitledBorder("Set JWT Headers"));
        // Set GridLayout to maximize component size
        jPanelJwtHeader.setLayout(new GridLayout(1, 1));

        // Add jTable for custom headers
        jPanelJwtHeader.add(addJtable(jwtHeaderTable,jHeaderTableModel, 80));
        return jPanelJwtHeader;
    }

    /**
     * Add Jwt Payload Table
     * @return Component
     */
    private Component addJwtPayload(){
        // Create a JPanel for Custom Header Attributes
        JPanel jPanelJwtPayload= new JPanel();

        // Set the titled border on the payload attributes panel
        jPanelJwtPayload.setBorder(getTitledBorder("Set JWT Payload Values"));
        // Set GridLayout to maximize component size
        jPanelJwtPayload.setLayout(new GridLayout(1, 1));

        // Add jTable for jwt payload
        jPanelJwtPayload.add(addJwtPayloadTable());
        return jPanelJwtPayload;
    }

    /**
     * Add Jwt Payload Claims Table
     * @return Component
     */
    private Component addJwtPayloadClaims(){
        // Create a JPanel for Custom Header Attributes
        JPanel jPanelJwtPayloadClaims= new JPanel();

        // Set the titled border on the payload attributes panel
        jPanelJwtPayloadClaims.setBorder(getTitledBorder("Set JWT Claims"));
        // Set GridLayout to maximize component size
        jPanelJwtPayloadClaims.setLayout(new GridLayout(1, 1));

        // Add jTable for jwt payload
        jPanelJwtPayloadClaims.add(addJtable(jwtPayloadClaimsTable,jClaimsTableModel,80));
        return jPanelJwtPayloadClaims;
    }

    /**
     * Create a JTable with default set of attribute keys
     * @return Component
     */
    private Component addJwtPayloadTable() {
        Box jwtTablePanel = Box.createHorizontalBox();

        // Add the table to a scroll pane
        JScrollPane scrollPane = new JScrollPane(jwtPayloadTable);
        scrollPane.setPreferredSize(new Dimension(300, 180));

        // Create a panel to hold the scroll pane
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(scrollPane, BorderLayout.CENTER);

        jwtTablePanel.add(panel);
        return jwtTablePanel;
    }


    /**
     * Create a empty JTtable with Add and Delete row buttons
     * @param jTable
     * @param jTableModel
     * @param height
     * @return Component
     */
    private Component addJtable(JTable jTable, DefaultTableModel jTableModel, int height){
        Box jwtTablePanel = Box.createHorizontalBox();

        // Create a JScrollPane and add the table to it
        JScrollPane scrollPaneHeaderTable = new JScrollPane(jTable);
        // set scroll pane size
        scrollPaneHeaderTable.setPreferredSize(new Dimension(300, height)); // Set preferred size of the scroll pane

        // Create a container JPanel to hold the scroll pane and button panel
        JPanel containerPanel = new JPanel(new BorderLayout());
        containerPanel.add(scrollPaneHeaderTable, BorderLayout.CENTER);
        // Adding Delete row and Add Row buttons to container JPanel
        containerPanel.add(addAddRowAndDeleteRowBtns(jTable,jTableModel), BorderLayout.SOUTH);

        // Add the container panel
        jwtTablePanel.add(containerPanel,BorderLayout.EAST);
        // Show the JFrame
        setVisible(true);
        return jwtTablePanel;
    }


    private Component addAddRowAndDeleteRowBtns(JTable jTable, DefaultTableModel jTableModel){
        // Create a JPanel to hold the buttons
        JPanel buttonPanel = new JPanel();

        // Create a JButton to add a new row to the table
        JButton addButtonHeaderTable = new JButton("Add Row");
        addButtonHeaderTable.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addTableRow(jTableModel);
            }
        });
        buttonPanel.add(addButtonHeaderTable);

        // Delete button, delete the select row from the table
        JButton deleteButton = new JButton("Delete Row");
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = jTable.getSelectedRow();
                if (selectedRow >= 0) {
                    jTableModel.removeRow(selectedRow);
                }
            }
        });
        buttonPanel.add(deleteButton);
        return buttonPanel;
    }

    private void addTableRow(DefaultTableModel model){
        Object[] rowData = {"",""};
        model.addRow(rowData);
    }

    /**
     * Set default values of JwtPreProcessor's JwtPayloadData object
     * @param jwtPreProcessor
     */
    private void addDefaultJwtPayloadAttributes(JwtPreProcessor jwtPreProcessor){
        String defaultValue =JWT_PAYLOAD_DEFAULT_ATTR_VALUE;
        HashMap<String,String> defaultAttributesMap = new HashMap<>();
        defaultAttributesMap.put(JWT_ATTR_AUDIENCE,defaultValue);
        defaultAttributesMap.put(JWT_ATTR_SUBJECT,defaultValue);
        defaultAttributesMap.put(JWT_ATTR_ID,defaultValue);
        defaultAttributesMap.put(JWT_ATTR_ISSUER,defaultValue);
        defaultAttributesMap.put(JWT_ATTR_EXPIRE_TIME, JWT_PAYLOAD_ATTR_DATE_FORMAT_VALUE);
        defaultAttributesMap.put(JWT_ATTR_NOT_BEFORE_TIME, JWT_PAYLOAD_ATTR_DATE_FORMAT_VALUE);
        defaultAttributesMap.put(JWT_ATTR_ISSUE_TIME, JWT_PAYLOAD_ATTR_DATE_FORMAT_VALUE);
        jwtPreProcessor.setJwtPayloadData(defaultAttributesMap);
    }

    /**
     * Define TextField for Jmeter Variable Name in UI
     * @return Component
     */
    private Component addJwtVariableTextField(){
        // Create a JPanel for Jmeter Variable
        JPanel jPanelJmeterVariable= new JPanel();
        // Set the titled border on theJmeter Variable  panel
        jPanelJmeterVariable.setBorder(getTitledBorder("Set Jmeter Variable Name"));
        jPanelJmeterVariable.setLayout(new GridLayout(1, 1));

        // Create a label and text field - Secret Key
        Box variableTextField = Box.createHorizontalBox();
        JLabel labelJvariable = new JLabel("Jmeter variable name to use:");
        // Add label and text box into horizontal-jbox
        variableTextField.add(labelJvariable);
        variableTextField.add(txtFieldVariableNameToUse,BorderLayout.EAST);

        // Add variable box into the variable panel
        jPanelJmeterVariable.add(variableTextField);
        return jPanelJmeterVariable;
    }

}
