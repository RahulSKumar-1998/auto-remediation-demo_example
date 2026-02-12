```diff
--- a/src/main/java/com/example/vuln/SQLInjection.java
+++ b/src/main/java/com/example/vuln/SQLInjection.java
@@ -11,9 +11,14 @@
 public class SQLInjection {
     public List<User> getUsers(Connection connection, String username) throws SQLException {
         List<User> users = new ArrayList<>();
-        Statement stmt = connection.createStatement();
-        String sql = "SELECT * FROM users WHERE username = '" + username + "'"; // Line 14
-        ResultSet rs = stmt.executeQuery(sql);
+        // Use PreparedStatement to prevent SQL Injection
+        String sql = "SELECT * FROM users WHERE username = ?";
+        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
+            pstmt.setString(1, username); // Set the parameter securely
+            try (ResultSet rs = pstmt.executeQuery()) {
+                while (rs.next()) {
+                    users.add(new User(rs.getInt("id"), rs.getString("username")));
+                }
+            }
+        }
-        while (rs.next()) {
-            users.add(new User(rs.getInt("id"), rs.getString("username")));
-        }
         return users;
     }
 }
```

**Explanation of the fix:**

The original code concatenated user input (`username`) directly into the SQL query string, creating a SQL Injection vulnerability. The fix replaces the `Statement` with a `PreparedStatement` and uses a parameter placeholder (`?`) in the SQL query. The user input is then bound to this parameter using `pstmt.setString(1, username)`, which safely escapes special characters and prevents injection attacks. The code also uses `try-with-resources` for `PreparedStatement` and `ResultSet` to ensure proper resource management.