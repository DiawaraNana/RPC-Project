// File: PasswordManagerServer.java

import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.security.*;
import java.sql.*;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import com.google.gson.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * PasswordManagerServer with a simple Swing GUI.
 * 
 * - Click “Start Server” to begin listening on the SSL port.
 * - The GUI shows real‐time log messages.
 * - Supports JSON actions: register, login, getAccounts, getPassword, createAccount, updateAccount, deleteAccount, searchAccounts.
 */
public class PasswordManagerServer {

    private static final int DEFAULT_PORT = 8443;
    private static final String DB_URL = "jdbc:sqlite:password_manager.db";
    private static final Map<String, String> activeSessions = new ConcurrentHashMap<>();
    private static final Gson gson = new Gson();
    private static SecretKey serverKey;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            int port = (args.length > 0) ? Integer.parseInt(args[0]) : DEFAULT_PORT;
            new ServerFrame(port).setVisible(true);
        });
    }

    /** Swing frame for the server UI. */
    static class ServerFrame extends JFrame {
        private final JTextArea logArea;
        private final JButton startButton;
        private final int port;
        private volatile boolean running = false;

        ServerFrame(int port) {
            super("Password Manager Server");
            this.port = port;
            setSize(600, 400);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLocationRelativeTo(null);

            Container cp = getContentPane();
            cp.setLayout(new BorderLayout(10, 10));
            cp.setBackground(Color.WHITE);

            JPanel top = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
            top.setBackground(Color.WHITE);

            JLabel title = new JLabel("Secure Password Manager Server");
            title.setFont(new Font("Segoe UI", Font.BOLD, 18));
            top.add(title);

            startButton = new JButton("Start Server");
            startButton.setFont(new Font("Segoe UI", Font.PLAIN, 14));
            startButton.addActionListener(e -> {
                startButton.setEnabled(false);
                new Thread(this::runServer).start();
            });
            top.add(startButton);

            cp.add(top, BorderLayout.NORTH);

            logArea = new JTextArea();
            logArea.setEditable(false);
            logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            JScrollPane scroll = new JScrollPane(logArea);
            cp.add(scroll, BorderLayout.CENTER);
        }

        /** Append a message to the log area (thread‐safe). */
        private void log(String msg) {
            SwingUtilities.invokeLater(() -> {
                logArea.append(msg + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }

        /** Main server‐loop: initialize DB, key, SSL, then accept clients. */
        private void runServer() {
            running = true;
            try {
                initializeDatabase();
                log("[SERVER] Database initialized.");

                generateServerKey();
                log("[SERVER] AES key generated.");

                SSLContext ctx = createSSLContext();
                SSLServerSocketFactory factory = ctx.getServerSocketFactory();
                SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port);
                log("[SERVER] Listening on SSL port " + port);

                while (running) {
                    SSLSocket clientSock = (SSLSocket) serverSocket.accept();
                    log("[SERVER] Accepted " + clientSock.getInetAddress());
                    new Thread(new ClientHandler(clientSock)).start();
                }

            } catch (Exception ex) {
                log("[SERVER] Exception: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
    }

    /** Initialize SQLite tables if they do not exist. */
    private static void initializeDatabase() throws SQLException {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            String createUsers = """
                CREATE TABLE IF NOT EXISTS users (
                  username TEXT PRIMARY KEY,
                  password_hash TEXT NOT NULL,
                  salt TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """;
            String createAccounts = """
                CREATE TABLE IF NOT EXISTS accounts (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  compte TEXT NOT NULL,
                  account_username TEXT NOT NULL,
                  encrypted_password TEXT NOT NULL,
                  notes TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(username) REFERENCES users(username)
                )
                """;
            conn.createStatement().execute(createUsers);
            conn.createStatement().execute(createAccounts);
        }
    }

    /** Generate a fresh AES‐256 key for encrypting account passwords. */
    private static void generateServerKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        serverKey = kg.generateKey();
    }

    /** Build SSLContext from a PKCS12 keystore (“keystore.p12” / password “cyber”). */
    private static SSLContext createSSLContext() throws Exception {
        String ksPath = "keystore.p12";
        String ksPass = "cyber";

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksPath)) {
            ks.load(fis, ksPass.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, ksPass.toCharArray());

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
        return ctx;
    }

    /** ClientHandler: receives JSON requests over SSL, dispatches, replies in JSON. */
    static class ClientHandler implements Runnable {
        private final SSLSocket socket;
        private BufferedReader in;
        private PrintWriter out;

        ClientHandler(SSLSocket sock) {
            this.socket = sock;
        }

        @Override
        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                String line;
                while ((line = in.readLine()) != null) {
                    processRequest(line);
                }
            } catch (IOException e) {
                System.err.println("[SERVER] ClientHandler I/O error: " + e.getMessage());
            } finally {
                try {
                    socket.close();
                } catch (IOException ignored) {}
            }
        }

        /** Parse JSON “line” and dispatch to the appropriate handler. */
        private void processRequest(String requestJson) {
            try {
                JsonObject req = gson.fromJson(requestJson, JsonObject.class);
                String action = req.get("action").getAsString();
                JsonObject resp;

               switch (action) {
    case "register":      resp = handleRegister(req);      break;
    case "login":         resp = handleLogin(req);         break;
    case "getAccounts":   resp = handleGetAccounts(req);   break;
    case "getPassword":   resp = handleGetPassword(req);   break;
    case "createAccount": resp = handleCreateAccount(req); break;
    case "updateAccount": resp = handleUpdateAccount(req); break;
    case "deleteAccount": resp = handleDeleteAccount(req); break;
    case "searchAccounts":resp = handleSearchAccounts(req);break;
    default:
        resp = new JsonObject();
        resp.addProperty("success", false);
        resp.addProperty("message", "Unknown action: " + action);
        break;
}


                out.println(gson.toJson(resp));

            } catch (Exception e) {
                JsonObject err = new JsonObject();
                err.addProperty("success", false);
                err.addProperty("message", "Server error: " + e.getMessage());
                out.println(gson.toJson(err));
            }
        }

        private JsonObject handleRegister(JsonObject req) {
            JsonObject resp = new JsonObject();
            try {
                String username = sanitize(req.get("username").getAsString());
                String password = req.get("password").getAsString();

                if (!isValidUsername(username) || !isValidPassword(password)) {
                    resp.addProperty("success", false);
                    resp.addProperty("message", "Invalid input format");
                    return resp;
                }

                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    String check = "SELECT username FROM users WHERE username = ?";
                    try (PreparedStatement ps = conn.prepareStatement(check)) {
                        ps.setString(1, username);
                        ResultSet rs = ps.executeQuery();
                        if (rs.next()) {
                            resp.addProperty("success", false);
                            resp.addProperty("message", "Username already exists");
                            return resp;
                        }
                    }

                    String salt = generateSalt();
                    String hashed = hash(password, salt);
                    String insert = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)";
                    try (PreparedStatement ps = conn.prepareStatement(insert)) {
                        ps.setString(1, username);
                        ps.setString(2, hashed);
                        ps.setString(3, salt);
                        ps.executeUpdate();
                    }

                    resp.addProperty("success", true);
                    resp.addProperty("message", "Registration successful");
                    System.out.println("[SERVER] Registered: " + username);
                }
            } catch (Exception e) {
                resp.addProperty("success", false);
                resp.addProperty("message", "Registration failed: " + e.getMessage());
            }
            return resp;
        }

        private JsonObject handleLogin(JsonObject req) {
            JsonObject resp = new JsonObject();
            try {
                String username = sanitize(req.get("username").getAsString());
                String password = req.get("password").getAsString();

                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    String query = "SELECT password_hash, salt FROM users WHERE username = ?";
                    try (PreparedStatement ps = conn.prepareStatement(query)) {
                        ps.setString(1, username);
                        ResultSet rs = ps.executeQuery();
                        if (rs.next()) {
                            String storedHash = rs.getString("password_hash");
                            String salt = rs.getString("salt");
                            String inputHash = hash(password, salt);
                            if (storedHash.equals(inputHash)) {
                                String token = generateSessionToken();
                                activeSessions.put(token, username);
                                resp.addProperty("success", true);
                                resp.addProperty("sessionToken", token);
                                resp.addProperty("message", "Login successful");
                                System.out.println("[SERVER] Logged in: " + username);
                            } else {
                                resp.addProperty("success", false);
                                resp.addProperty("message", "Invalid credentials");
                            }
                        } else {
                            resp.addProperty("success", false);
                            resp.addProperty("message", "Invalid credentials");
                        }
                    }
                }
            } catch (Exception e) {
                resp.addProperty("success", false);
                resp.addProperty("message", "Login failed: " + e.getMessage());
            }
            return resp;
        }

        private JsonObject handleGetAccounts(JsonObject req) {
            JsonObject resp = new JsonObject();
            try {
                String token = req.get("sessionToken").getAsString();
                String user = activeSessions.get(token);
                if (user == null) {
                    resp.addProperty("success", false);
                    resp.addProperty("message", "Invalid session");
                    return resp;
                }

                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    String query = "SELECT id, compte, account_username, notes FROM accounts WHERE username = ?";
                    try (PreparedStatement ps = conn.prepareStatement(query)) {
                        ps.setString(1, user);
                        ResultSet rs = ps.executeQuery();

                        JsonArray arr = new JsonArray();
                        while (rs.next()) {
                            JsonObject acct = new JsonObject();
                            acct.addProperty("id", rs.getInt("id"));
                            acct.addProperty("compte", rs.getString("compte"));
                            acct.addProperty("account_username", rs.getString("account_username"));
                            acct.addProperty("notes", rs.getString("notes"));
                            arr.add(acct);
                        }
                        resp.addProperty("success", true);
                        resp.add("accounts", arr);
                        System.out.println("[SERVER] [" + user + "] Listed accounts");
                    }
                }
            } catch (Exception e) {
                resp.addProperty("success", false);
                resp.addProperty("message", "Error fetching accounts: " + e.getMessage());
            }
            return resp;
        }

        private JsonObject handleGetPassword(JsonObject req) {
            JsonObject resp = new JsonObject();
            try {
                String token = req.get("sessionToken").getAsString();
                String user = activeSessions.get(token);
                if (user == null) {
                    resp.addProperty("success", false);
                    resp.addProperty("message", "Invalid session");
                    return resp;
                }

                int accountId = req.get("id").getAsInt();
                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    String query = "SELECT encrypted_password FROM accounts WHERE id = ? AND username = ?";
                    try (PreparedStatement ps = conn.prepareStatement(query)) {
                        ps.setInt(1, accountId);
                        ps.setString(2, user);
                        ResultSet rs = ps.executeQuery();
                        if (rs.next()) {
                            String enc = rs.getString("encrypted_password");
                            String plain = decrypt(enc);
                            resp.addProperty("success", true);
                            resp.addProperty("password", plain);
                            System.out.println("[SERVER] [" + user + "] Retrieved password for account ID " + accountId);
                        } else {
                            resp.addProperty("success", false);
                            resp.addProperty("message", "Account not found");
                        }
                    }
                }
            } catch (Exception e) {
                resp.addProperty("success", false);
                resp.addProperty("message", "Error retrieving password: " + e.getMessage());
            }
            return resp;
        }

        private JsonObject handleCreateAccount(JsonObject req) {
            JsonObject resp = new JsonObject();
            try {
                String token = req.get("sessionToken").getAsString();
                String user = activeSessions.get(token);
                if (user == null) {
                    resp.addProperty("success", false);
                    resp.addProperty("message", "Invalid session");
                    return resp;
                }

                String compte = sanitize(req.get("compte").getAsString());
                String acctUser = sanitize(req.get("account_username").getAsString());
                String password = req.get("password").getAsString();
                String notes = sanitize(req.get("notes").getAsString());
                String encPwd = encrypt(password);

                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    String insert = "INSERT INTO accounts (username, compte, account_username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)";
                    try (PreparedStatement ps = conn.prepareStatement(insert)) {
                        ps.setString(1, user);
                        ps.setString(2, compte);
                        ps.setString(3, acctUser);
                        ps.setString(4, encPwd);
                        ps.setString(5, notes);
                        ps.executeUpdate();
                    }
                    resp.addProperty("success", true);
                    resp.addProperty("message", "Account created");
                    System.out.println("[SERVER] [" + user + "] Created account: " + compte);
                }
            } catch (Exception e) {
                resp.addProperty("success", false);
                resp.addProperty("message", "Create failed: " + e.getMessage());
            }
            return resp;
        }

        private JsonObject handleUpdateAccount(JsonObject req) {
            JsonObject resp = new JsonObject();
            try {
                String token = req.get("sessionToken").getAsString();
                String user = activeSessions.get(token);
                if (user == null) {
                    resp.addProperty("success", false);
                    resp.addProperty("message", "Invalid session");
                    return resp;
                }

                int id = req.get("id").getAsInt();
                String compte = sanitize(req.get("compte").getAsString());
                String acctUser = sanitize(req.get("account_username").getAsString());
                String password = req.get("password").getAsString();
                String notes = sanitize(req.get("notes").getAsString());
                String encPwd = encrypt(password);

                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    String update = "UPDATE accounts SET compte=?, account_username=?, encrypted_password=?, notes=? WHERE id=? AND username=?";
                    try (PreparedStatement ps = conn.prepareStatement(update)) {
                        ps.setString(1, compte);
                        ps.setString(2, acctUser);
                        ps.setString(3, encPwd);
                        ps.setString(4, notes);
                        ps.setInt(5, id);
                        ps.setString(6, user);
                        int rows = ps.executeUpdate();
                        if (rows > 0) {
                            resp.addProperty("success", true);
                            resp.addProperty("message", "Account updated");
                            System.out.println("[SERVER] [" + user + "] Updated account ID " + id);
                        } else {
                            resp.addProperty("success", false);
                            resp.addProperty("message", "Account not found or unauthorized");
                        }
                    }
                }
            } catch (Exception e) {
                resp.addProperty("success", false);
                resp.addProperty("message", "Update failed: " + e.getMessage());
            }
            return resp;
        }

        private JsonObject handleDeleteAccount(JsonObject req) {
            JsonObject resp = new JsonObject();
            try {
                String token = req.get("sessionToken").getAsString();
                String user = activeSessions.get(token);
                if (user == null) {
                    resp.addProperty("success", false);
                    resp.addProperty("message", "Invalid session");
                    return resp;
                }

                int id = req.get("id").getAsInt();
                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    String del = "DELETE FROM accounts WHERE id=? AND username=?";
                    try (PreparedStatement ps = conn.prepareStatement(del)) {
                        ps.setInt(1, id);
                        ps.setString(2, user);
                        int rows = ps.executeUpdate();
                        if (rows > 0) {
                            resp.addProperty("success", true);
                            resp.addProperty("message", "Account deleted");
                            System.out.println("[SERVER] [" + user + "] Deleted account ID " + id);
                        } else {
                            resp.addProperty("success", false);
                            resp.addProperty("message", "Account not found or unauthorized");
                        }
                    }
                }
            } catch (Exception e) {
                resp.addProperty("success", false);
                resp.addProperty("message", "Delete failed: " + e.getMessage());
            }
            return resp;
        }

        private JsonObject handleSearchAccounts(JsonObject req) {
            JsonObject resp = new JsonObject();
            try {
                String token = req.get("sessionToken").getAsString();
                String user = activeSessions.get(token);
                if (user == null) {
                    resp.addProperty("success", false);
                    resp.addProperty("message", "Invalid session");
                    return resp;
                }

                String term = sanitize(req.get("searchTerm").getAsString());
                try (Connection conn = DriverManager.getConnection(DB_URL)) {
                    String q = "SELECT id, compte, account_username, notes FROM accounts WHERE username=? AND (compte LIKE ? OR account_username LIKE ?)";
                    try (PreparedStatement ps = conn.prepareStatement(q)) {
                        ps.setString(1, user);
                        ps.setString(2, "%" + term + "%");
                        ps.setString(3, "%" + term + "%");
                        ResultSet rs = ps.executeQuery();

                        JsonArray arr = new JsonArray();
                        while (rs.next()) {
                            JsonObject acct = new JsonObject();
                            acct.addProperty("id", rs.getInt("id"));
                            acct.addProperty("compte", rs.getString("compte"));
                            acct.addProperty("account_username", rs.getString("account_username"));
                            acct.addProperty("notes", rs.getString("notes"));
                            arr.add(acct);
                        }
                        resp.addProperty("success", true);
                        resp.add("accounts", arr);
                        System.out.println("[SERVER] [" + user + "] Searched accounts for '" + term + "'");
                    }
                }
            } catch (Exception e) {
                resp.addProperty("success", false);
                resp.addProperty("message", "Search failed: " + e.getMessage());
            }
            return resp;
        }
    }

    // ─── Utility Methods ──────────────────────────────────────────────────

    private static String generateSalt() {
        SecureRandom rnd = new SecureRandom();
        byte[] salt = new byte[16];
        rnd.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static String hash(String password, String salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Base64.getDecoder().decode(salt));
        byte[] hashed = md.digest(password.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hashed);
    }

    private static String generateSessionToken() {
        SecureRandom rnd = new SecureRandom();
        byte[] t = new byte[32];
        rnd.nextBytes(t);
        return Base64.getEncoder().encodeToString(t);
    }

    private static String encrypt(String plain) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, serverKey);
        byte[] enc = c.doFinal(plain.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(enc);
    }

    private static String decrypt(String cipherText) throws Exception {
        byte[] data = Base64.getDecoder().decode(cipherText);
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, serverKey);
        byte[] dec = c.doFinal(data);
        return new String(dec, "UTF-8");
    }

    private static String sanitize(String s) {
        if (s == null) return "";
        return s.replaceAll("[<>\"'%;()&+]", "");
    }

    private static boolean isValidUsername(String s) {
        return s != null && s.matches("^[a-zA-Z0-9_.-]{3,50}$");
    }

    private static boolean isValidPassword(String s) {
        return s != null && s.length() >= 6;
    }
}
