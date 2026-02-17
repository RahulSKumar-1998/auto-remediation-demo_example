package com.example.vuln;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class XSS {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");

        // VULNERABILITY: Reflected Cross-Site Scripting (XSS)
        // The input 'name' is echoed back to the user without any sanitization or
        // escaping.
        response.getWriter().write("<h1>Hello, " + name + "</h1>");
    }
}
