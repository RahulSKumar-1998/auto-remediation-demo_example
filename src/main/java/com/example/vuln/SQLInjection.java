package com.example.vuln;

import com.example.util.Database;

public class SQLInjection {
    public void getUser(String userId) {
        // VULNERABILITY: SQL Injection
        // The userId is concatenated directly into the query string.
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Database.executeQuery(query);
    }
}
