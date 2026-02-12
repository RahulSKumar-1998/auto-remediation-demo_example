package com.example.vuln;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SQLInjection {

    public void getUser(String userId) {
        try {
            Connection conn = com.example.util.Database.getConnection();
            Statement stmt = conn.createStatement();

            // VULNERABILITY: SQL Injection
            // Concatenating user input directly into the query
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";

            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                System.out.println("User: " + rs.getString("username"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
