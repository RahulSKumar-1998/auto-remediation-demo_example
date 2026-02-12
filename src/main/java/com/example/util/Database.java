package com.example.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Database {
    public static Connection getConnection() throws SQLException {
        // Dummy connection for compilation purposes
        return DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
    }
}
