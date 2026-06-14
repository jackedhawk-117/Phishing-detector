package com.example.phishingdetector.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents the result of a phishing analysis performed by the Groq LLM.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PhishingResult {

    @JsonProperty("isPhishing")
    private boolean isPhishing;

    @JsonProperty("confidence")
    private String confidence;

    @JsonProperty("reasoning")
    private String reasoning;

    public PhishingResult() {}

    public PhishingResult(boolean isPhishing, String confidence, String reasoning) {
        this.isPhishing = isPhishing;
        this.confidence = confidence;
        this.reasoning = reasoning;
    }

    public boolean isPhishing() {
        return isPhishing;
    }

    public void setPhishing(boolean phishing) {
        isPhishing = phishing;
    }

    public String getConfidence() {
        return confidence;
    }

    public void setConfidence(String confidence) {
        this.confidence = confidence;
    }

    public String getReasoning() {
        return reasoning;
    }

    public void setReasoning(String reasoning) {
        this.reasoning = reasoning;
    }

    @Override
    public String toString() {
        return "PhishingResult{" +
                "isPhishing=" + isPhishing +
                ", confidence='" + confidence + '\'' +
                ", reasoning='" + reasoning + '\'' +
                '}';
    }
}
