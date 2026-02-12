```java
// src/main/java/com/example/vuln/XSS.java
package com.example.vuln;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils; // ADDED IMPORT

@RestController
public class XSS {

    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        // FIX: HTML-encode the user-provided 'name' parameter to prevent Cross-Site Scripting (XSS).
        // This ensures that any special HTML characters in the input are converted to their entity
        // equivalents, preventing them from being interpreted as active content by the browser.
        String encodedName = HtmlUtils.htmlEscape(name); // MODIFIED LINE (originally used 'name' directly)
        return "<h1>Hello, " + encodedName + "!</h1>";
    }
}
```