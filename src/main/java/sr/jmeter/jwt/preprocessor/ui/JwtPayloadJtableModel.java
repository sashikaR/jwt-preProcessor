package sr.jmeter.jwt.preprocessor.ui;

import javax.swing.table.DefaultTableModel;

public class JwtPayloadJtableModel extends DefaultTableModel {
    public JwtPayloadJtableModel(Object[] columnNames, int rowCount) {
        super(columnNames, rowCount);
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column != 0; // Allow editing only for column 1 (Attribute Value)
    }
}
