package com.scamdetector.controller;

import com.scamdetector.dto.ScamAnalysisResult;
import com.scamdetector.model.Scan;
import com.scamdetector.model.User;
import com.scamdetector.service.*;
import com.scamdetector.util.ResponseBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * WhatsApp Webhook Controller
 *
 * Receives incoming WhatsApp messages from Twilio,
 * routes them through the scam detection pipeline,
 * and returns TwiML response.
 *
 * Endpoint: POST /webhook/whatsapp
 */
@RestController
@RequestMapping("/webhook")
public class WhatsAppWebhookController {

    private static final Logger log = LoggerFactory.getLogger(WhatsAppWebhookController.class);

    private final ScamDetectionService scamDetectionService;
    private final UserService userService;
    private final ScanService scanService;
    private final SafetyAdvisor safetyAdvisor;

    public WhatsAppWebhookController(
            ScamDetectionService scamDetectionService,
            UserService userService,
            ScanService scanService,
            SafetyAdvisor safetyAdvisor
    ) {
        this.scamDetectionService = scamDetectionService;
        this.userService = userService;
        this.scanService = scanService;
        this.safetyAdvisor = safetyAdvisor;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Main Webhook Endpoint
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Twilio sends form-encoded POST with fields:
     *   Body = message text
     *   From = sender's WhatsApp number (whatsapp:+919876543210)
     */
    @PostMapping(
            value = "/whatsapp",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_XML_VALUE
    )
    public ResponseEntity<String> handleWhatsAppMessage(
            @RequestParam(value = "Body",    required = false) String body,
            @RequestParam(value = "From",    required = false) String from,
            @RequestParam(value = "NumMedia",required = false, defaultValue = "0") String numMedia
    ) {
        log.info("Webhook received | From: {} | Body length: {}", from, body != null ? body.length() : 0);

        // ── Input Validation ──────────────────────────────────────────────────
        if (body == null || body.isBlank()) {
            log.warn("Empty message received from {}", from);
            String response = ResponseBuilder.wrapInTwiml(
                    "Please send a text message to analyze. Forward any suspicious WhatsApp message to me!"
            );
            return ResponseEntity.ok(response);
        }

        String senderPhone = cleanPhoneNumber(from);
        String messageText = body.trim();

        try {
            // ── Get or Create User ────────────────────────────────────────────
            boolean isNewUser = userService.isNewUser(senderPhone);
            User user = userService.getOrCreateUser(senderPhone);

            // ── New User → Send Welcome ────────────────────────────────────────
            if (isNewUser) {
                String welcome = ResponseBuilder.wrapInTwiml(ResponseBuilder.buildWelcomeResponse());
                return ResponseEntity.ok(welcome);
            }

            // ── Emergency Mode ────────────────────────────────────────────────
            if (safetyAdvisor.isEmergencyMessage(messageText)) {
                log.info("Emergency mode triggered for {}", senderPhone);
                String emergency = ResponseBuilder.wrapInTwiml(ResponseBuilder.buildEmergencyResponse());
                return ResponseEntity.ok(emergency);
            }

            // ── History Request ───────────────────────────────────────────────
            if (safetyAdvisor.isHistoryRequest(messageText)) {
                List<Scan> recentScans = scanService.getRecentScans(user);
                String history = ResponseBuilder.wrapInTwiml(ResponseBuilder.buildHistoryResponse(recentScans));
                return ResponseEntity.ok(history);
            }

            // ── Help Request ──────────────────────────────────────────────────
            if (safetyAdvisor.isHelpRequest(messageText)) {
                String help = ResponseBuilder.wrapInTwiml(ResponseBuilder.buildHelpResponse());
                return ResponseEntity.ok(help);
            }

            // ── Full Scam Analysis ────────────────────────────────────────────
            log.info("Running scam analysis for user {}", senderPhone);
            ScamAnalysisResult result = scamDetectionService.analyze(messageText);

            // ── Save to Database ──────────────────────────────────────────────
            scanService.saveScan(messageText, result, user);
            userService.incrementScanCount(user);

            // ── Build Response ────────────────────────────────────────────────
            String responseMessage = ResponseBuilder.buildScamAnalysisResponse(result);
            String twiml = ResponseBuilder.wrapInTwiml(responseMessage);

            log.info("Analysis complete | Risk: {} ({}) | User: {}", result.getRiskLevel(), result.getRiskScore(), senderPhone);
            return ResponseEntity.ok(twiml);

        } catch (Exception e) {
            log.error("Error processing webhook from {}: {}", senderPhone, e.getMessage(), e);
            String errorResponse = ResponseBuilder.wrapInTwiml(ResponseBuilder.buildErrorResponse());
            return ResponseEntity.ok(errorResponse);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Health / Verification Endpoint
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * GET endpoint for Twilio webhook verification and health checks.
     */
    @GetMapping("/whatsapp")
    public ResponseEntity<String> webhookVerify() {
        return ResponseEntity.ok("WhatsApp Scam Detector webhook is active ✅");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Private Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Strip Twilio's "whatsapp:" prefix from phone number.
     * whatsapp:+919876543210 → +919876543210
     */
    private String cleanPhoneNumber(String from) {
        if (from == null) return "unknown";
        return from.replace("whatsapp:", "").trim();
    }
}
