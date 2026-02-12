package com.example.vuln;

public class XSS {

    public String renderPage(String username) {
        // VULNERABILITY: Cross-Site Scripting (Reflected XSS)
        // Returning user input directly to the browser without escaping/sanitization
        return "<html><body><h1>Welcome, " + username + "!</h1></body></html>";
    }
}
