package com.example.phishingdetector.service;

import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Service;
import java.util.regex.Pattern;

@Service
public class PrivacyService {
    private static final Pattern EMAIL_PATTERN = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");
    private static final Pattern PHONE_PATTERN = Pattern.compile("\\b\\d{3}[.-]?\\d{3}[.-]?\\d{4}\\b");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\b\\d{4}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}\\b");

    public String anonymizeEmail(String emailText) {
        if (emailText == null || emailText.isEmpty()) {
            return emailText;
        }

        String sanitized = StringEscapeUtils.escapeHtml4(emailText);
        sanitized = EMAIL_PATTERN.matcher(sanitized).replaceAll("[EMAIL]");
        sanitized = PHONE_PATTERN.matcher(sanitized).replaceAll("[PHONE]");
        sanitized = CREDIT_CARD_PATTERN.matcher(sanitized).replaceAll("[CARD]");
        sanitized = sanitized.replaceAll("\\b\\d{4,}\\b", "[NUMBERS]");
        sanitized = sanitized.replaceAll("\\b[A-Z][a-z]+ [A-Z][a-z]+\\b", "[NAME]");

        return sanitized;
    }
}