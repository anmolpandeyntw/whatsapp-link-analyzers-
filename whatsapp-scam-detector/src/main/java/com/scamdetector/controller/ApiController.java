package com.scamdetector.controller;

import com.scamdetector.dto.ScamAnalysisResult;
import com.scamdetector.service.ScamDetectionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST API Controller for direct JSON-based testing.
 * Use this with Postman to test without Twilio.
 *
 * POST /api/analyze  → analyze a message and get JSON result
 * GET  /api/health   → health check
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    private final ScamDetectionService scamDetectionService;

    public ApiController(ScamDetectionService scamDetectionService) {
        this.scamDetectionService = scamDetectionService;
    }

    /**
     * Direct message analysis endpoint (for testing with Postman).
     *
     * POST /api/analyze
     * Body: { "message": "You have won a lottery! Click http://bit.ly/fake to claim now!" }
     */
    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeMessage(@RequestBody Map<String, String> request) {
        String message = request.get("message");

        if (message == null || message.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Field 'message' is required and cannot be empty"
            ));
        }

        if (message.length() > 2000) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Message too long. Max 2000 characters."
            ));
        }

        ScamAnalysisResult result = scamDetectionService.analyze(message);
        return ResponseEntity.ok(result);
    }

    /**
     * Health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "WhatsApp Scam Detector",
                "version", "1.0.0"
        ));
    }
}
