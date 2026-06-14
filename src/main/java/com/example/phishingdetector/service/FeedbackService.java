package com.example.phishingdetector.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Logs user feedback on phishing predictions.
 * With the switch to Groq LLM, there is no local model to retrain,
 * so feedback is logged for future analytics / fine-tuning purposes.
 */
@Service
public class FeedbackService {
    private static final Logger logger = LoggerFactory.getLogger(FeedbackService.class);

    private final PrivacyService privacyService;

    public FeedbackService(PrivacyService privacyService) {
        this.privacyService = privacyService;
    }

    /**
     * Records user feedback on whether the system's phishing prediction was correct.
     *
     * @param emailText        the original email text
     * @param systemPrediction what the system predicted (true = phishing)
     * @param wasCorrect       whether the user confirmed the prediction as correct
     */
    public void processFeedback(String emailText, boolean systemPrediction, boolean wasCorrect) {
        String anonymizedText = privacyService.anonymizeEmail(emailText);
        boolean actualLabel = wasCorrect ? systemPrediction : !systemPrediction;

        logger.info("Feedback received — prediction: {}, actual: {}, correct: {}, email (anonymized): {}",
                systemPrediction ? "PHISHING" : "LEGIT",
                actualLabel ? "PHISHING" : "LEGIT",
                wasCorrect,
                anonymizedText);
    }
}