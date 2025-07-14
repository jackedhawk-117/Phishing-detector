package com.example.phishingdetector.util;

import java.util.Arrays;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class EmailFeatureExtractor {
    private static final Set<String> URGENCY_WORDS = Set.of(
            "urgent", "immediate", "verify", "suspended", "action required",
            "required", "alert", "warning", "important", "attention"
    );

    private static final Set<String> COMMON_BRANDS = Set.of(
            "paypal", "amazon", "netflix", "bank", "microsoft", "apple",
            "google", "facebook", "linkedin", "twitter", "irs", "gov"
    );

    private static final Pattern URL_PATTERN = Pattern.compile("https?://\\S+");
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("@([\\w.-]+)");
    private static final Pattern BRAND_PATTERN = createBrandPattern();

    public static boolean containsUrl(String text) {
        return URL_PATTERN.matcher(text).find();
    }

    public static int countUrgencyWords(String text) {
        String lowerText = text.toLowerCase();
        return (int) URGENCY_WORDS.stream()
                .filter(word -> lowerText.contains(word))
                .count();
    }

    public static String extractDomain(String email) {
        var matcher = DOMAIN_PATTERN.matcher(email);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static boolean hasSuspiciousSubject(String text) {
        return text.toLowerCase().matches(".*(alert|warning|urgent|action required|immediate).*");
    }

    public static double linkToTextRatio(String text) {
        int linkLength = URL_PATTERN.matcher(text).results()
                .mapToInt(m -> m.group().length()).sum();
        return text.isEmpty() ? 0 : (double) linkLength / text.length();
    }

    public static boolean hasSpoofedBrands(String text) {
        return BRAND_PATTERN.matcher(text.toLowerCase()).find();
    }

    public static int countSensitiveKeywords(String text) {
        return (int) COMMON_BRANDS.stream()
                .filter(brand -> text.toLowerCase().contains(brand))
                .count();
    }

    private static Pattern createBrandPattern() {
        String pattern = COMMON_BRANDS.stream()
                .map(brand -> "(?<!\\w)" + Pattern.quote(brand) + "(?!\\w)")
                .collect(Collectors.joining("|"));
        return Pattern.compile(pattern);
    }
}