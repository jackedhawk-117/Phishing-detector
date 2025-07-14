package com.example.phishingdetector.service;

import com.example.phishingdetector.util.EmailFeatureExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

@Service
public class FeedbackService {
    private static final Logger logger = LoggerFactory.getLogger(FeedbackService.class);
    private final PhishingModelService modelService;
    private final PrivacyService privacyService;

    public FeedbackService(PhishingModelService modelService,
                           PrivacyService privacyService) {
        this.modelService = modelService;
        this.privacyService = privacyService;
    }

    public void processFeedback(String emailText, boolean systemPrediction,
                                boolean wasCorrect) throws IOException {
        try {
            String anonymizedText = privacyService.anonymizeEmail(emailText);
            boolean actualLabel = systemPrediction != wasCorrect;

            appendToArffFile(anonymizedText, actualLabel);
            modelService.scheduleRetraining();
        } catch (IOException e) {
            logger.error("Failed to process feedback for email: {}", emailText, e);
            throw new IOException("Failed to process feedback due to file system error", e);
        } catch (Exception e) {
            logger.error("Unexpected error processing feedback for email: {}", emailText, e);
            throw new IOException("Failed to process feedback due to unexpected error", e);
        }
    }

    private void appendToArffFile(String emailText, boolean isPhishing) throws IOException {
        Path path = Paths.get("src/main/resources/data/emails.arff");
        if (!Files.exists(path)) {
            logger.error("ARFF file not found at path: {}", path.toAbsolutePath());
            throw new IOException("Training data file not found at: " + path.toAbsolutePath());
        }

        String sanitizedText = emailText.replace("\"", "\\\"")
                .replace("\n", "\\n");

        String newInstance = String.format("%n\"%s\",%d,%d,%s",
                sanitizedText,
                EmailFeatureExtractor.containsUrl(emailText) ? 1 : 0,
                EmailFeatureExtractor.countUrgencyWords(emailText),
                isPhishing ? "phishing" : "legit");

        try {
            Files.write(path, newInstance.getBytes(), StandardOpenOption.APPEND);
            logger.info("Successfully added new training instance to ARFF file");
        } catch (IOException e) {
            logger.error("Failed to write to ARFF file at path: {}", path.toAbsolutePath(), e);
            throw new IOException("Failed to update training data file", e);
        }
    }
}