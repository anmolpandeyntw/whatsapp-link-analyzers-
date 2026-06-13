package com.scamdetector.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.Optional;

/**
 * Google Gemini AI Integration for scam message classification.
 *
 * Uses Gemini 1.5 Flash (free tier) to classify messages and
 * extract risk level, confidence, and one-line reason.
 *
 * Falls back gracefully if API is unavailable or fails.
 */
@Service
public class GeminiAIService {

    private static final Logger log = LoggerFactory.getLogger(GeminiAIService.class);

    @Value("${gemini.api.key}")
    private String geminiApiKey;

    @Value("${gemini.api.url}")
    private String geminiApiUrl;

    @Value("${app.ai-timeout-seconds:10}")
    private int timeoutSeconds;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient;

    public GeminiAIService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Result DTO
    // ─────────────────────────────────────────────────────────────────────────

    public static class AIResult {
        public String riskLevel = "UNKNOWN";
        public int confidence = 0;
        public String reason = "AI analysis unavailable";
        public boolean success = false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Main API Call
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Send message to Gemini for scam classification.
     * Returns AIResult. Falls back if API fails.
     */
    public AIResult analyzeMessage(String message) {
        AIResult result = new AIResult();

        if (geminiApiKey == null || geminiApiKey.isBlank() || geminiApiKey.equals("your-gemini-api-key-here")) {
            log.warn("Gemini API key not configured. Using rule-only mode.");
            result.reason = "AI not configured — using rule-based analysis only";
            return result;
        }

        try {
            String prompt = buildPrompt(message);
            String requestBody = buildRequestBody(prompt);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(geminiApiUrl + "?key=" + geminiApiKey))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                parseResponse(response.body(), result);
            } else {
                log.error("Gemini API returned status {}: {}", response.statusCode(), response.body());
                result.reason = "AI service temporarily unavailable";
            }

        } catch (java.net.http.HttpTimeoutException e) {
            log.warn("Gemini API timeout — falling back to rule-based analysis");
            result.reason = "AI analysis timed out — rule-based result used";
        } catch (Exception e) {
            log.error("Gemini API error: {}", e.getMessage());
            result.reason = "AI analysis failed — rule-based result used";
        }

        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Prompt Builder
    // ─────────────────────────────────────────────────────────────────────────

    private String buildPrompt(String message) {
        // Limit message to avoid token overflow
        String truncated = message.length() > 500
                ? message.substring(0, 500) + "..."
                : message;

        return """
                You are a scam detection expert. Analyze this WhatsApp message and classify it.
                
                Message:
                "%s"
                
                Respond in EXACTLY this format (no extra text):
                RISK_LEVEL: [LOW or MEDIUM or HIGH]
                CONFIDENCE: [number 0-100]
                REASON: [one sentence explaining why]
                
                Guidelines:
                - HIGH: clear scam indicators (fake prizes, OTP requests, phishing links, threats)
                - MEDIUM: suspicious but could be legitimate (unknown sender, some urgency)
                - LOW: appears to be a genuine message
                """.formatted(truncated);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Request Body Builder
    // ─────────────────────────────────────────────────────────────────────────

    private String buildRequestBody(String prompt) {
        // Build JSON manually to avoid extra dependencies
        String escapedPrompt = prompt
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");

        return """
                {
                  "contents": [
                    {
                      "parts": [
                        {
                          "text": "%s"
                        }
                      ]
                    }
                  ],
                  "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 150
                  }
                }
                """.formatted(escapedPrompt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Response Parser
    // ─────────────────────────────────────────────────────────────────────────

    private void parseResponse(String responseBody, AIResult result) {
        try {
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode candidates = root.path("candidates");

            if (candidates.isArray() && !candidates.isEmpty()) {
                String text = candidates.get(0)
                        .path("content")
                        .path("parts")
                        .get(0)
                        .path("text")
                        .asText("");

                log.debug("Gemini response text: {}", text);
                extractFields(text, result);
                result.success = true;
            }

        } catch (Exception e) {
            log.error("Failed to parse Gemini response: {}", e.getMessage());
        }
    }

    /**
     * Extract structured fields from Gemini's text response.
     */
    private void extractFields(String text, AIResult result) {
        String[] lines = text.split("\n");

        for (String line : lines) {
            line = line.trim();

            if (line.startsWith("RISK_LEVEL:")) {
                String level = line.replace("RISK_LEVEL:", "").trim().toUpperCase();
                if (level.contains("HIGH")) result.riskLevel = "HIGH";
                else if (level.contains("MEDIUM")) result.riskLevel = "MEDIUM";
                else if (level.contains("LOW")) result.riskLevel = "LOW";

            } else if (line.startsWith("CONFIDENCE:")) {
                String conf = line.replace("CONFIDENCE:", "").trim()
                        .replaceAll("[^0-9]", "");
                try {
                    result.confidence = Math.min(100, Math.max(0, Integer.parseInt(conf)));
                } catch (NumberFormatException e) {
                    result.confidence = 50;
                }

            } else if (line.startsWith("REASON:")) {
                result.reason = line.replace("REASON:", "").trim();
            }
        }
    }
}
