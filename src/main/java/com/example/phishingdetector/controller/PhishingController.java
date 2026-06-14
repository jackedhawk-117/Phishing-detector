package com.example.phishingdetector.controller;

import com.example.phishingdetector.model.PhishingResult;
import com.example.phishingdetector.service.FeedbackService;
import com.example.phishingdetector.service.GroqPhishingService;
import com.example.phishingdetector.util.EmailFeatureExtractor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/phishing")
@CrossOrigin(origins = "*")
public class PhishingController {
    private final GroqPhishingService groqService;
    private final FeedbackService feedbackService;

    public PhishingController(GroqPhishingService groqService,
                              FeedbackService feedbackService) {
        this.groqService = groqService;
        this.feedbackService = feedbackService;
    }

    @GetMapping("/user")
    public ResponseEntity<?> getUserInfo(@AuthenticationPrincipal OidcUser user) {
        if (user == null) {
            return ResponseEntity.ok(Map.of("authenticated", false));
        }
        return ResponseEntity.ok(user.getClaims());
    }

    @PostMapping("/detect")
    public ResponseEntity<?> detectPhishing(
            @RequestParam String emailText,
            @AuthenticationPrincipal OidcUser user) {
        try {
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Authentication required"));
            }

            // Call Groq LLM for phishing analysis
            PhishingResult result = groqService.analyze(emailText);

            // Also extract local features as supplementary info
            Map<String, Object> features = extractFeatures(emailText);
            features.put("user", user.getEmail());

            Map<String, Object> response = new HashMap<>();
            response.put("phishing", result.isPhishing());
            response.put("confidence", result.getConfidence());
            response.put("reasoning", result.getReasoning());
            response.put("features", features);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to analyze email: " + e.getMessage()));
        }
    }

    @PostMapping("/feedback")
    public ResponseEntity<?> submitFeedback(
            @RequestBody FeedbackRequest request,
            @AuthenticationPrincipal OidcUser user) {
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        feedbackService.processFeedback(
                request.getEmailText(),
                request.getSystemPrediction(),
                request.getWasCorrect()
        );
        return ResponseEntity.ok().build();
    }

    private Map<String, Object> extractFeatures(String emailText) {
        Map<String, Object> features = new HashMap<>();
        features.put("has_url", EmailFeatureExtractor.containsUrl(emailText));
        features.put("urgency_words", EmailFeatureExtractor.countUrgencyWords(emailText));
        features.put("suspicious_subject", EmailFeatureExtractor.hasSuspiciousSubject(emailText));
        features.put("link_ratio", EmailFeatureExtractor.linkToTextRatio(emailText));
        features.put("spoofed_brands", EmailFeatureExtractor.hasSpoofedBrands(emailText));
        features.put("sensitive_keywords", EmailFeatureExtractor.countSensitiveKeywords(emailText));
        return features;
    }

    public static class FeedbackRequest {
        private String emailText;
        private boolean systemPrediction;
        private boolean wasCorrect;

        // Getters and setters
        public String getEmailText() { return emailText; }
        public void setEmailText(String emailText) { this.emailText = emailText; }
        public boolean getSystemPrediction() { return systemPrediction; }
        public void setSystemPrediction(boolean systemPrediction) { this.systemPrediction = systemPrediction; }
        public boolean getWasCorrect() { return wasCorrect; }
        public void setWasCorrect(boolean wasCorrect) { this.wasCorrect = wasCorrect; }
    }
}