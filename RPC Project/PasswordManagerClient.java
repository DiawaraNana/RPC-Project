// File: PasswordManagerClient.java

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.AbstractTableModel;
import javax.net.ssl.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import com.google.gson.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;


/**
 * PasswordManagerClient with:
 *  - Connection frame (host/port)
 *  - Login / Register
 *  - Main table of accounts
 *  - “Consulter le mot de passe” (show plaintext)
 *  - “Déconnecter” (end session, go back to login)
 */
public class PasswordManagerClient {
    private static final Color PRIMARY_COLOR   = new Color(240, 240, 240);
    private static final Color SECONDARY_COLOR = new Color(220, 220, 220);
    private static final Color ACCENT_COLOR    = new Color(70, 130, 180);
    private static final Color DANGER_COLOR    = new Color(220, 53, 69);
    private static final Color SUCCESS_COLOR   = new Color(40, 167, 69);
    private static final Color TEXT_COLOR      = new Color(50, 50, 50);

    private static final Gson gson = new Gson();
    private static String sessionToken = null;
    private static SSLSocket socket;
    private static BufferedReader in;
    private static PrintWriter out;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            setLookAndFeel();
            new ConnectionFrame();
        });
    }

    private static void setLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            Font font = new Font("Segoe UI", Font.PLAIN, 14);
            UIManager.put("Button.font", font);
            UIManager.put("Label.font", font);
            UIManager.put("TextField.font", font);
            UIManager.put("PasswordField.font", font);
            UIManager.put("TextArea.font", font);
            UIManager.put("Table.font", font);
            UIManager.put("TableHeader.font", font.deriveFont(Font.BOLD));
        } catch (Exception ignored) {}
    }

    /** First frame: connect to host/port over SSL. */
    static class ConnectionFrame extends JFrame {
        private final JTextField hostField;
        private final JTextField portField;

        ConnectionFrame() {
            setTitle("Connect to Password Manager Server");
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(450, 250);
            setLocationRelativeTo(null);
            getContentPane().setBackground(PRIMARY_COLOR);
            hostField = new JTextField("localhost");
            portField = new JTextField("8443");
            initComponents();
            setVisible(true);
        }

        private void initComponents() {
            JPanel panel = new JPanel(new GridBagLayout());
            panel.setBackground(PRIMARY_COLOR);
            panel.setBorder(BorderFactory.createEmptyBorder(20, 30, 20, 30));

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(10, 10, 10, 10);
            gbc.fill = GridBagConstraints.HORIZONTAL;

            JLabel title = new JLabel("Connect to Server", SwingConstants.CENTER);
            title.setFont(new Font("Segoe UI", Font.BOLD, 20));
            title.setForeground(TEXT_COLOR);
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
            panel.add(title, gbc);

            gbc.gridwidth = 1;
            JLabel hostLabel = createLabel("Host:");
            gbc.gridx = 0; gbc.gridy = 1;
            panel.add(hostLabel, gbc);
            gbc.gridx = 1;
            panel.add(createTextField(hostField), gbc);

            JLabel portLabel = createLabel("Port:");
            gbc.gridx = 0; gbc.gridy = 2;
            panel.add(portLabel, gbc);
            gbc.gridx = 1;
            panel.add(createTextField(portField), gbc);

            JButton connectBtn = createButton("Connect", ACCENT_COLOR);
            connectBtn.addActionListener(e -> connectAction());
            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
            panel.add(connectBtn, gbc);

            add(panel);
        }

        private void connectAction() {
            String host = hostField.getText().trim();
            String portText = portField.getText().trim();
            if (host.isEmpty() || portText.isEmpty()) {
                showError("Please fill all fields");
                return;
            }
            try {
                int port = Integer.parseInt(portText);
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{ new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                }}, new SecureRandom());
                SSLSocketFactory factory = ctx.getSocketFactory();
                socket = (SSLSocket) factory.createSocket(host, port);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);
                JOptionPane.showMessageDialog(this, "Connected!", "Success", JOptionPane.INFORMATION_MESSAGE);
                dispose();
                new LoginFrame();
            } catch (NumberFormatException ex) {
                showError("Port must be a number");
            } catch (Exception ex) {
                showError("Connection failed: " + ex.getMessage());
            }
        }

        private void showError(String msg) {
            JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Frame for user login or registration. */
    static class LoginFrame extends JFrame {
        private final JTextField userField = new JTextField();
        private final JPasswordField passField = new JPasswordField();

        LoginFrame() {
            setTitle("Password Manager - Login");
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(450, 350);
            setLocationRelativeTo(null);
            getContentPane().setBackground(PRIMARY_COLOR);
            initComponents();
            setVisible(true);
        }

        private void initComponents() {
            JPanel panel = new JPanel(new GridBagLayout());
            panel.setBackground(PRIMARY_COLOR);
            panel.setBorder(BorderFactory.createEmptyBorder(30, 40, 30, 40));

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(10, 10, 10, 10);
            gbc.fill = GridBagConstraints.HORIZONTAL;

            JLabel title = new JLabel("Password Manager", SwingConstants.CENTER);
            title.setFont(new Font("Segoe UI", Font.BOLD, 22));
            title.setForeground(TEXT_COLOR);
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
            panel.add(title, gbc);

            gbc.gridwidth = 1;
            JLabel userLabel = createLabel("Username:");
            gbc.gridx = 0; gbc.gridy = 1;
            panel.add(userLabel, gbc);
            gbc.gridx = 1;
            panel.add(createTextField(userField), gbc);

            JLabel passLabel = createLabel("Password:");
            gbc.gridx = 0; gbc.gridy = 2;
            panel.add(passLabel, gbc);
            gbc.gridx = 1;
            panel.add(createPasswordField(passField), gbc);

            JPanel btnPanel = new JPanel(new GridLayout(1, 2, 15, 0));
            btnPanel.setBackground(PRIMARY_COLOR);
            btnPanel.setBorder(BorderFactory.createEmptyBorder(15, 0, 0, 0));

            JButton loginBtn = createButton("Login", SUCCESS_COLOR);
            loginBtn.addActionListener(e -> loginAction());
            JButton regBtn = createButton("Register", ACCENT_COLOR);
            regBtn.addActionListener(e -> {
                dispose();
                new RegisterFrame();
            });

            btnPanel.add(loginBtn);
            btnPanel.add(regBtn);

            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
            panel.add(btnPanel, gbc);

            add(panel);
        }

        private void loginAction() {
            String u = userField.getText().trim();
            String p = new String(passField.getPassword());
            if (u.isEmpty() || p.isEmpty()) {
                showError("Please fill all fields");
                return;
            }
            try {
                JsonObject req = new JsonObject();
                req.addProperty("action", "login");
                req.addProperty("username", u);
                req.addProperty("password", p);
                out.println(gson.toJson(req));
                String resp = in.readLine();
                JsonObject r = gson.fromJson(resp, JsonObject.class);
                if (r.get("success").getAsBoolean()) {
                    sessionToken = r.get("sessionToken").getAsString();
                    JOptionPane.showMessageDialog(this, "Login successful!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    dispose();
                    new MainFrame(u);
                } else {
                    showError(r.get("message").getAsString());
                }
            } catch (Exception ex) {
                showError("Login failed: " + ex.getMessage());
            }
            passField.setText("");
        }

        private void showError(String msg) {
            JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Frame for user registration. */
    static class RegisterFrame extends JFrame {
        private final JTextField userField = new JTextField();
        private final JPasswordField passField = new JPasswordField();
        private final JPasswordField confirmField = new JPasswordField();

        RegisterFrame() {
            setTitle("Password Manager - Register");
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(450, 400);
            setLocationRelativeTo(null);
            getContentPane().setBackground(PRIMARY_COLOR);
            initComponents();
            setVisible(true);
        }

        private void initComponents() {
            JPanel panel = new JPanel(new GridBagLayout());
            panel.setBackground(PRIMARY_COLOR);
            panel.setBorder(BorderFactory.createEmptyBorder(30, 40, 30, 40));

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(10, 10, 10, 10);
            gbc.fill = GridBagConstraints.HORIZONTAL;

            JLabel title = new JLabel("Create Account", SwingConstants.CENTER);
            title.setFont(new Font("Segoe UI", Font.BOLD, 22));
            title.setForeground(TEXT_COLOR);
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
            panel.add(title, gbc);

            gbc.gridwidth = 1;
            JLabel userLabel = createLabel("Username:");
            gbc.gridx = 0; gbc.gridy = 1;
            panel.add(userLabel, gbc);
            gbc.gridx = 1;
            panel.add(createTextField(userField), gbc);

            JLabel passLabel = createLabel("Password:");
            gbc.gridx = 0; gbc.gridy = 2;
            panel.add(passLabel, gbc);
            gbc.gridx = 1;
            panel.add(createPasswordField(passField), gbc);

            JLabel confirmLabel = createLabel("Confirm Password:");
            gbc.gridx = 0; gbc.gridy = 3;
            panel.add(confirmLabel, gbc);
            gbc.gridx = 1;
            panel.add(createPasswordField(confirmField), gbc);

            JPanel btnPanel = new JPanel(new GridLayout(1, 2, 15, 0));
            btnPanel.setBackground(PRIMARY_COLOR);
            btnPanel.setBorder(BorderFactory.createEmptyBorder(15, 0, 0, 0));

            JButton regBtn = createButton("Register", SUCCESS_COLOR);
            regBtn.addActionListener(e -> registerAction());
            JButton backBtn = createButton("Back", SECONDARY_COLOR);
            backBtn.addActionListener(e -> {
                dispose();
                new LoginFrame();
            });

            btnPanel.add(regBtn);
            btnPanel.add(backBtn);

            gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
            panel.add(btnPanel, gbc);

            add(panel);
        }

        private void registerAction() {
            String u = userField.getText().trim();
            String p = new String(passField.getPassword());
            String c = new String(confirmField.getPassword());
            if (u.isEmpty() || p.isEmpty() || c.isEmpty()) {
                showError("Please fill all fields");
                return;
            }
            if (!p.equals(c)) {
                showError("Passwords do not match");
                passField.setText("");
                confirmField.setText("");
                return;
            }
            if (p.length() < 6) {
                showError("Password must be at least 6 characters");
                return;
            }
            try {
                JsonObject req = new JsonObject();
                req.addProperty("action", "register");
                req.addProperty("username", u);
                req.addProperty("password", p);
                out.println(gson.toJson(req));
                String resp = in.readLine();
                JsonObject r = gson.fromJson(resp, JsonObject.class);
                if (r.get("success").getAsBoolean()) {
                    JOptionPane.showMessageDialog(this, "Registration successful!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    dispose();
                    new LoginFrame();
                } else {
                    showError(r.get("message").getAsString());
                }
            } catch (Exception ex) {
                showError("Registration failed: " + ex.getMessage());
            }
            passField.setText("");
            confirmField.setText("");
        }

        private void showError(String msg) {
            JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Main application frame showing the list of accounts. */
    static class MainFrame extends JFrame {
        private final String username;
        private final java.util.List<Account> accounts = new ArrayList<>();
        private final JTable table;
        private final AccountTableModel model;
        private final JTextField searchField = new JTextField();

        MainFrame(String username) {
            this.username = username;
            setTitle("Password Manager - " + username);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(900, 600);
            setLocationRelativeTo(null);
            getContentPane().setBackground(PRIMARY_COLOR);
            model = new AccountTableModel(accounts);
            table = new JTable(model);
            initComponents();
            loadAccounts();
            setVisible(true);
        }

        private void initComponents() {
            setLayout(new BorderLayout());

            // HEADER
            JPanel header = new JPanel(new BorderLayout());
            header.setBackground(PRIMARY_COLOR);
            header.setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
            JLabel title = new JLabel("Mes Comptes", SwingConstants.LEFT);
            title.setFont(new Font("Segoe UI", Font.BOLD, 20));
            title.setForeground(TEXT_COLOR);
            JLabel userLabel = new JLabel("Utilisateur : " + username, SwingConstants.RIGHT);
            userLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
            userLabel.setForeground(TEXT_COLOR);
            header.add(title, BorderLayout.WEST);
            header.add(userLabel, BorderLayout.EAST);

            // SEARCH
            JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
            searchPanel.setBackground(SECONDARY_COLOR);
            searchPanel.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 15));
            JLabel searchLabel = createLabel("Rechercher :");
            searchPanel.add(searchLabel);
            searchField.setPreferredSize(new Dimension(250, 30));
            searchPanel.add(searchField);
            JButton searchBtn = createButton("Rechercher", ACCENT_COLOR);
            searchBtn.addActionListener(e -> searchAccounts());
            JButton allBtn = createButton("Afficher tout", ACCENT_COLOR);
            allBtn.addActionListener(e -> loadAccounts());
            searchPanel.add(searchBtn);
            searchPanel.add(allBtn);

            // TABLE
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.setRowHeight(30);
            table.setIntercellSpacing(new Dimension(0, 0));
            table.setShowGrid(false);
            DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
            centerRenderer.setHorizontalAlignment(JLabel.CENTER);
            for (int i = 0; i < table.getColumnCount(); i++) {
                table.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
            }
            JTableHeader th = table.getTableHeader();
            th.setBackground(ACCENT_COLOR);
            th.setForeground(Color.WHITE);
            th.setFont(new Font("Segoe UI", Font.BOLD, 14));
            table.setTableHeader(th);
            JScrollPane scroll = new JScrollPane(table);
            scroll.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));

            // BUTTONS
            JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 15));
            btnPanel.setBackground(PRIMARY_COLOR);
            btnPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 20, 0));

            JButton createBtn = createButton("Créer", SUCCESS_COLOR);
            createBtn.addActionListener(e -> createAccount());
            JButton editBtn = createButton("Modifier", ACCENT_COLOR);
            editBtn.addActionListener(e -> editAccount());
            JButton deleteBtn = createButton("Supprimer", DANGER_COLOR);
            deleteBtn.addActionListener(e -> deleteAccount());
            JButton consultBtn = createButton("Consulter le mot de passe", ACCENT_COLOR);
            consultBtn.addActionListener(e -> consultPassword());
            consultBtn.setEnabled(false);
            JButton disconnectBtn = createButton("Déconnecter", DANGER_COLOR);
            disconnectBtn.addActionListener(e -> disconnect());

            btnPanel.add(createBtn);
            btnPanel.add(editBtn);
            btnPanel.add(deleteBtn);
            btnPanel.add(consultBtn);
            btnPanel.add(disconnectBtn);

            // Enable “Consulter” only if a row is selected
            table.getSelectionModel().addListSelectionListener(e -> {
                consultBtn.setEnabled(table.getSelectedRow() >= 0);
            });

            // Layout
            JPanel topPanel = new JPanel(new BorderLayout());
            topPanel.add(header, BorderLayout.NORTH);
            topPanel.add(searchPanel, BorderLayout.SOUTH);

            add(topPanel, BorderLayout.NORTH);
            add(scroll, BorderLayout.CENTER);
            add(btnPanel, BorderLayout.SOUTH);
        }

        private void loadAccounts() {
            try {
                JsonObject req = new JsonObject();
                req.addProperty("action", "getAccounts");
                req.addProperty("sessionToken", sessionToken);
                out.println(gson.toJson(req));
                String resp = in.readLine();
                JsonObject r = gson.fromJson(resp, JsonObject.class);
                if (r.get("success").getAsBoolean()) {
                    accounts.clear();
                    JsonArray arr = r.getAsJsonArray("accounts");
                    for (JsonElement el : arr) {
                        JsonObject obj = el.getAsJsonObject();
                        Account a = new Account(
                                obj.get("id").getAsInt(),
                                obj.get("compte").getAsString(),
                                obj.get("account_username").getAsString(),
                                obj.get("notes").getAsString()
                        );
                        accounts.add(a);
                    }
                    model.fireTableDataChanged();
                } else {
                    showError(r.get("message").getAsString());
                }
            } catch (Exception e) {
                showError("Cannot load accounts: " + e.getMessage());
            }
        }

        private void searchAccounts() {
            String term = searchField.getText().trim();
            if (term.isEmpty()) {
                loadAccounts();
                return;
            }
            try {
                JsonObject req = new JsonObject();
                req.addProperty("action", "searchAccounts");
                req.addProperty("sessionToken", sessionToken);
                req.addProperty("searchTerm", term);
                out.println(gson.toJson(req));
                String resp = in.readLine();
                JsonObject r = gson.fromJson(resp, JsonObject.class);
                if (r.get("success").getAsBoolean()) {
                    accounts.clear();
                    JsonArray arr = r.getAsJsonArray("accounts");
                    for (JsonElement el : arr) {
                        JsonObject obj = el.getAsJsonObject();
                        Account a = new Account(
                                obj.get("id").getAsInt(),
                                obj.get("compte").getAsString(),
                                obj.get("account_username").getAsString(),
                                obj.get("notes").getAsString()
                        );
                        accounts.add(a);
                    }
                    model.fireTableDataChanged();
                } else {
                    showError(r.get("message").getAsString());
                }
            } catch (Exception e) {
                showError("Search failed: " + e.getMessage());
            }
        }

        private void createAccount() {
            AccountDialog dlg = new AccountDialog(this, "Créer un compte", null);
            Account a = dlg.getAccount();
            if (a != null) {
                try {
                    JsonObject req = new JsonObject();
                    req.addProperty("action", "createAccount");
                    req.addProperty("sessionToken", sessionToken);
                    req.addProperty("compte", a.getCompte());
                    req.addProperty("account_username", a.getAccountUsername());
                    req.addProperty("password", a.getPassword());
                    req.addProperty("notes", a.getNotes());
                    out.println(gson.toJson(req));
                    String resp = in.readLine();
                    JsonObject r = gson.fromJson(resp, JsonObject.class);
                    if (r.get("success").getAsBoolean()) {
                        showSuccess("Account created");
                        loadAccounts();
                    } else {
                        showError(r.get("message").getAsString());
                    }
                } catch (Exception e) {
                    showError("Create failed: " + e.getMessage());
                }
            }
        }

        private void editAccount() {
            int row = table.getSelectedRow();
            if (row < 0) {
                showWarning("Sélectionnez un compte d'abord");
                return;
            }
            Account orig = accounts.get(row);
            AccountDialog dlg = new AccountDialog(this, "Modifier le compte", orig);
            Account updated = dlg.getAccount();
            if (updated != null) {
                try {
                    JsonObject req = new JsonObject();
                    req.addProperty("action", "updateAccount");
                    req.addProperty("sessionToken", sessionToken);
                    req.addProperty("id", orig.getId());
                    req.addProperty("compte", updated.getCompte());
                    req.addProperty("account_username", updated.getAccountUsername());
                    req.addProperty("password", updated.getPassword());
                    req.addProperty("notes", updated.getNotes());
                    out.println(gson.toJson(req));
                    String resp = in.readLine();
                    JsonObject r = gson.fromJson(resp, JsonObject.class);
                    if (r.get("success").getAsBoolean()) {
                        showSuccess("Account updated");
                        loadAccounts();
                    } else {
                        showError(r.get("message").getAsString());
                    }
                } catch (Exception e) {
                    showError("Update failed: " + e.getMessage());
                }
            }
        }

        private void deleteAccount() {
            int row = table.getSelectedRow();
            if (row < 0) {
                showWarning("Sélectionnez un compte d'abord");
                return;
            }
            Account a = accounts.get(row);
            int c = JOptionPane.showConfirmDialog(
                    this,
                    "Supprimer le compte « " + a.getCompte() + " » ?",
                    "Confirmer",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );
            if (c == JOptionPane.YES_OPTION) {
                try {
                    JsonObject req = new JsonObject();
                    req.addProperty("action", "deleteAccount");
                    req.addProperty("sessionToken", sessionToken);
                    req.addProperty("id", a.getId());
                    out.println(gson.toJson(req));
                    String resp = in.readLine();
                    JsonObject r = gson.fromJson(resp, JsonObject.class);
                    if (r.get("success").getAsBoolean()) {
                        showSuccess("Account deleted");
                        loadAccounts();
                    } else {
                        showError(r.get("message").getAsString());
                    }
                } catch (Exception e) {
                    showError("Delete failed: " + e.getMessage());
                }
            }
        }

        private void consultPassword() {
            int row = table.getSelectedRow();
            if (row < 0) {
                showWarning("Sélectionnez un compte d'abord");
                return;
            }
            Account a = accounts.get(row);
            try {
                JsonObject req = new JsonObject();
                req.addProperty("action", "getPassword");
                req.addProperty("sessionToken", sessionToken);
                req.addProperty("id", a.getId());
                out.println(gson.toJson(req));
                String resp = in.readLine();
                JsonObject r = gson.fromJson(resp, JsonObject.class);
                if (r.get("success").getAsBoolean()) {
                    String pwd = r.get("password").getAsString();
                    JOptionPane.showMessageDialog(
                            this,
                            "Mot de passe pour « " + a.getCompte() + " » :\n\n" + pwd,
                            "Mot de passe en clair",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } else {
                    showError(r.get("message").getAsString());
                }
            } catch (Exception e) {
                showError("Impossible de récupérer le mot de passe: " + e.getMessage());
            }
        }

        private void disconnect() {
            int c = JOptionPane.showConfirmDialog(
                    this,
                    "Voulez-vous vous déconnecter ?",
                    "Confirmer déconnexion",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE
            );
            if (c == JOptionPane.YES_OPTION) {
                sessionToken = null;
                accounts.clear();
                dispose();
                try {
                    socket.close();
                } catch (IOException ignored) {}
                new ConnectionFrame();
            }
        }

        private void showError(String msg) {
            JOptionPane.showMessageDialog(this, msg, "Erreur", JOptionPane.ERROR_MESSAGE);
        }

        private void showSuccess(String msg) {
            JOptionPane.showMessageDialog(this, msg, "Succès", JOptionPane.INFORMATION_MESSAGE);
        }

        private void showWarning(String msg) {
            JOptionPane.showMessageDialog(this, msg, "Attention", JOptionPane.WARNING_MESSAGE);
        }
    }

    /** Dialog for creating or editing an Account. */
    static class AccountDialog extends JDialog {
        private final JTextField compteField = new JTextField();
        private final JTextField userField = new JTextField();
        private final JPasswordField passField = new JPasswordField();
        private final JTextArea notesArea = new JTextArea();
        private Account account; // If null = create, else edit

        AccountDialog(Frame parent, String title, Account account) {
            super(parent, title, true);
            this.account = (account == null) ? new Account(0, "", "", "") : new Account(account);
            initComponents();
            setSize(500, 400);
            setLocationRelativeTo(parent);
            setVisible(true);
        }

        private void initComponents() {
            JPanel panel = new JPanel(new GridBagLayout());
            panel.setBackground(PRIMARY_COLOR);
            panel.setBorder(BorderFactory.createEmptyBorder(20, 30, 20, 30));

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(10, 10, 10, 10);
            gbc.anchor = GridBagConstraints.WEST;
            gbc.fill = GridBagConstraints.HORIZONTAL;

            JLabel lblCompte = createLabel("Nom du compte:");
            gbc.gridx = 0; gbc.gridy = 0;
            panel.add(lblCompte, gbc);
            compteField.setText(account.getCompte());
            gbc.gridx = 1;
            panel.add(compteField, gbc);

            JLabel lblUser = createLabel("Username:");
            gbc.gridx = 0; gbc.gridy = 1;
            panel.add(lblUser, gbc);
            userField.setText(account.getAccountUsername());
            gbc.gridx = 1;
            panel.add(userField, gbc);

            JLabel lblPass = createLabel("Mot de passe:");
            gbc.gridx = 0; gbc.gridy = 2;
            panel.add(lblPass, gbc);
            passField.setText(""); // never show saved
            gbc.gridx = 1;
            panel.add(passField, gbc);

            JLabel lblNotes = createLabel("Notes:");
            gbc.gridx = 0; gbc.gridy = 3;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            panel.add(lblNotes, gbc);

            notesArea.setText(account.getNotes());
            notesArea.setLineWrap(true);
            notesArea.setWrapStyleWord(true);
            JScrollPane scroll = new JScrollPane(notesArea);
            scroll.setPreferredSize(new Dimension(300, 150));
            gbc.gridx = 1;
            panel.add(scroll, gbc);

            JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 0));
            btnPanel.setBackground(PRIMARY_COLOR);
            btnPanel.setBorder(BorderFactory.createEmptyBorder(20, 0, 0, 0));

            JButton saveBtn = createButton("Save", SUCCESS_COLOR);
            saveBtn.addActionListener(e -> saveAction());

            JButton cancelBtn = createButton("Cancel", DANGER_COLOR);
            cancelBtn.addActionListener(e -> {
                account = null;
                dispose();
            });

            btnPanel.add(saveBtn);
            btnPanel.add(cancelBtn);

            gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.CENTER;
            panel.add(btnPanel, gbc);

            add(panel);
        }

        private void saveAction() {
            String c = compteField.getText().trim();
            String u = userField.getText().trim();
            String p = new String(passField.getPassword());
            String n = notesArea.getText().trim();
            if (c.isEmpty() || u.isEmpty() || p.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please fill required fields", "Warning", JOptionPane.WARNING_MESSAGE);
                return;
            }
            account.setCompte(c);
            account.setAccountUsername(u);
            account.setPassword(p);
            account.setNotes(n);
            dispose();
        }

        Account getAccount() {
            return account;
        }
    }

    /** Plain‐old Account object. */
    static class Account {
        private int id;
        private String compte;
        private String accountUsername;
        private String notes;
        private String password; // transient, not displayed in table

        Account(int id, String compte, String accountUsername, String notes) {
            this.id = id;
            this.compte = compte;
            this.accountUsername = accountUsername;
            this.notes = notes;
        }

        Account(Account other) {
            this.id = other.id;
            this.compte = other.compte;
            this.accountUsername = other.accountUsername;
            this.notes = other.notes;
        }

        int getId() { return id; }
        String getCompte() { return compte; }
        String getAccountUsername() { return accountUsername; }
        String getNotes() { return notes; }
        String getPassword() { return password; }

        void setPassword(String p) { this.password = p; }
        void setCompte(String c) { this.compte = c; }
        void setAccountUsername(String u) { this.accountUsername = u; }
        void setNotes(String n) { this.notes = n; }
    }

    /** TableModel for displaying accounts in a JTable. */
    static class AccountTableModel extends AbstractTableModel {
        private final java.util.List<Account> accounts;
        private final String[] cols = { "Account Name", "Username", "Notes" };

        AccountTableModel(java.util.List<Account> accounts) {
            this.accounts = accounts;
        }

        @Override
        public int getRowCount() {
            return accounts.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public Object getValueAt(int row, int col) {
            Account a = accounts.get(row);
            return switch (col) {
                case 0 -> a.getCompte();
                case 1 -> a.getAccountUsername();
                case 2 -> a.getNotes();
                default -> null;
            };
        }

        @Override
        public String getColumnName(int col) {
            return cols[col];
        }
    }

    // ─── Styled Component Utilities ─────────────────────────────────

    private static JLabel createLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        return lbl;
    }

    private static JTextField createTextField(JTextField f) {
        f.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(SECONDARY_COLOR, 1),
            BorderFactory.createEmptyBorder(8, 8, 8, 8)
        ));
        return f;
    }

    private static JPasswordField createPasswordField(JPasswordField f) {
        f.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(SECONDARY_COLOR, 1),
            BorderFactory.createEmptyBorder(8, 8, 8, 8)
        ));
        return f;
    }

    private static JButton createButton(String text, Color bg) {
        JButton btn = new JButton(text);
        btn.setBackground(bg);
        btn.setOpaque(true);
        btn.setContentAreaFilled(true);
        btn.setBorderPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(bg.darker(), 1),
            BorderFactory.createEmptyBorder(8, 20, 8, 20)
        ));
        btn.setFocusPainted(false);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 14));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return btn;
    }
}
