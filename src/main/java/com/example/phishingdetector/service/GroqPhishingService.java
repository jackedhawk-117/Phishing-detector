package com.example.phishingdetector.service;

import com.example.phishingdetector.model.PhishingResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.List;
import java.util.Map;

/**
 * Calls the Groq REST API (OpenAI-compatible chat completions endpoint)
 * to classify an email as phishing or legitimate using a hosted LLM.
 */
@Service
public class GroqPhishingService {

    private static final Logger logger = LoggerFactory.getLogger(GroqPhishingService.class);

    private static final String SYSTEM_PROMPT = """
            You are a cybersecurity expert specializing in phishing email detection.
            Analyze the provided email and determine if it is a phishing attempt.
            Look for: urgency/fear tactics, suspicious URLs or domains, requests for credentials or personal info,
            spoofed sender addresses, grammar inconsistencies, mismatched branding, and unexpected attachments.
            Respond ONLY in this JSON format:
            {
              "isPhishing": true/false,
              "confidence": "HIGH" | "MEDIUM" | "LOW",
              "reasoning": "brief explanation"
            }""";

    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    private final String model;

    public GroqPhishingService(
            @Value("${groq.api.key}") String apiKey,
            @Value("${groq.api.url}") String apiUrl,
            @Value("${groq.model}") String model,
            ObjectMapper objectMapper) {

        this.webClient = WebClient.builder()
                .baseUrl(apiUrl)
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + apiKey)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
        this.objectMapper = objectMapper;
        this.model = model;
    }

    /**
     * Sends the email content to the Groq LLM for phishing analysis.
     *
     * @param emailContent the full email text (subject + body)
     * @return a {@link PhishingResult} with the verdict, confidence, and reasoning
     */
    public PhishingResult analyze(String emailContent) {
        try {
            Map<String, Object> requestBody = buildRequest(emailContent);

            String responseJson = webClient.post()
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            return parseResponse(responseJson);

        } catch (WebClientResponseException e) {
            logger.error("Groq API returned HTTP {}: {}", e.getStatusCode(), e.getResponseBodyAsString(), e);
            return fallbackResult("Groq API error: " + e.getStatusCode());
        } catch (Exception e) {
            logger.error("Failed to call Groq API for phishing analysis", e);
            return fallbackResult("Groq API unreachable: " + e.getMessage());
        }
    }

    // ───────────────────── private helpers ─────────────────────

    private Map<String, Object> buildRequest(String emailContent) {
        return Map.of(
                "model", model,
                "messages", List.of(
                        Map.of("role", "system", "content", SYSTEM_PROMPT),
                        Map.of("role", "user", "content", "Analyze this email for phishing:\n\n" + emailContent)
                ),
                "temperature", 0.1,
                "max_tokens", 512
        );
    }

    private PhishingResult parseResponse(String responseJson) {
        try {
            JsonNode root = objectMapper.readTree(responseJson);
            JsonNode choices = root.path("choices");

            if (choices.isEmpty() || choices.isMissingNode()) {
                logger.warn("Groq response contained no choices: {}", responseJson);
                return fallbackResult("Empty response from Groq API");
            }

            String content = choices.get(0)
                    .path("message")
                    .path("content")
                    .asText();

            // The LLM might wrap JSON in a markdown code fence — strip it
            content = stripCodeFence(content);

            return objectMapper.readValue(content, PhishingResult.class);

        } catch (Exception e) {
            logger.error("Failed to parse Groq response: {}", responseJson, e);
            return fallbackResult("Failed to parse LLM response");
        }
    }

    /**
     * Strips optional markdown code fences (```json ... ```) that LLMs
     * sometimes add around their JSON output.
     */
    private String stripCodeFence(String content) {
        if (content == null) return "";
        content = content.trim();
        if (content.startsWith("```")) {
            // Remove opening fence (```json or ```)
            int firstNewline = content.indexOf('\n');
            if (firstNewline != -1) {
                content = content.substring(firstNewline + 1);
            }
            // Remove closing fence
            if (content.endsWith("```")) {
                content = content.substring(0, content.length() - 3);
            }
            content = content.trim();
        }
        return content;
    }

    /**
     * Returns a safe default when the Groq API is unreachable or returns garbage.
     */
    private PhishingResult fallbackResult(String reason) {
        return new PhishingResult(false, "LOW", reason);
    }
}
