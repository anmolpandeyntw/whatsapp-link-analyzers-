package com.scamdetector.service;

import com.scamdetector.util.LinkUtils;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Rule-Based Scam Detection Engine.
 *
 * Analyzes a message using:
 * - Categorized keyword matching
 * - Pattern detection (phone, currency, APK)
 * - Heuristic signal combination
 */
@Component
public class RuleBasedDetector {

    // ─── Scam Keyword Categories ──────────────────────────────────────────────

    private static final List<String> SCAM_KEYWORDS = List.of(
            "lottery", "prize", "winner", "won", "winning", "reward",
            "congratulations", "selected", "lucky", "jackpot",
            "claim your", "you have won", "free gift", "gift card",
            "cash prize", "bumper prize", "lucky draw"
    );
    private static final List<String> INDIRECT_OTP_KEYWORDS = List.of(
            "6 digit", "6-digit", "six digit",
            "digit number", "digit code",
            "credential", "credentials",
            "verification code", "verify code",
            "confirmation code", "confirm code",
            "secret code", "secret number",
            "access code", "security code",
            "fix your account", "secure your account",
            "account recovery", "account verify",
            "i will fix", "we will fix",
            "send me the code", "give me the code",
            "share the code", "forward the code",
            "that code", "the code"
    );private static final List<String> INDIRECT_CREDENTIAL_KEYWORDS = List.of(
            "credential", "login detail",
            "username and password", "id and password",
            "account detail", "account information",
            "personal detail", "personal information",
            "what i send", "what we sent",
            "sent to your", "sent to you",
            "received on your", "you received"
    );private static final List<String> SOCIAL_ENGINEERING_KEYWORDS = List.of(
            "i will fix your", "we will fix your",
            "help you fix", "fix your account",
            "on your behalf", "from our side",
            "our team will", "our executive will",
            "technical team", "support team",
            "just share", "just send",
            "just give", "only share",
            "dont worry", "don't worry",
            "100% safe", "completely safe",
            "trust me", "i promise"
    );

    private static final List<String> URGENCY_KEYWORDS = List.of(
            "urgent", "act now", "limited time", "hurry", "expire",
            "expires today", "last chance", "immediately", "asap",
            "within 24 hours", "deadline", "don't wait", "quick",
            "time sensitive", "before it's too late"
    );

    private static final List<String> SENSITIVE_KEYWORDS = List.of(
            "otp", "password", "pin", "bank account", "credit card",
            "debit card", "kyc", "aadhar", "pan card", "cvv",
            "account number", "ifsc", "netbanking", "atm pin",
            "upi", "paytm", "phonepe", "google pay", "verification code"
    );

    private static final List<String> FINANCIAL_KEYWORDS = List.of(
            "loan", "investment", "profit", "returns", "interest",
            "earn money", "work from home", "part time job",
            "easy money", "guaranteed profit", "double your money",
            "bitcoin", "crypto", "trading", "forex", "scheme"
    );

    private static final List<String> THREAT_KEYWORDS = List.of(
            "account blocked", "account suspended", "legal action",
            "police", "arrest", "court notice", "fir", "cyber crime",
            "your number will be blocked", "disconnected", "penalty"
    );

    private static final List<String> PHISHING_KEYWORDS = List.of(
            "verify your account", "update your details", "confirm your",
            "click here", "click the link", "visit link", "login to claim",
            "register now", "download", "install", "apk"
    );

    // ─── Score Weights ────────────────────────────────────────────────────────

    private static final int SCAM_KEYWORD_SCORE     = 15;
    private static final int URGENCY_KEYWORD_SCORE  = 12;
    private static final int SENSITIVE_KEYWORD_SCORE = 20;
    private static final int FINANCIAL_KEYWORD_SCORE = 10;
    private static final int THREAT_KEYWORD_SCORE   = 18;
    private static final int PHISHING_KEYWORD_SCORE  = 15;

    // Combination bonuses
    private static final int SCAM_PLUS_URGENCY_BONUS     = 20;
    private static final int SENSITIVE_PLUS_LINK_BONUS   = 25;
    private static final int THREAT_PLUS_URGENCY_BONUS   = 20;
    private static final int FINANCIAL_PLUS_LINK_BONUS   = 20;

    // Pattern scores
    private static final int PHONE_PATTERN_SCORE    = 10;
    private static final int CURRENCY_PATTERN_SCORE = 10;
    private static final int APK_MENTION_SCORE      = 30;
    private static final int ALL_CAPS_SCORE         = 8;

    // ─────────────────────────────────────────────────────────────────────────
    //  Public API
    // ─────────────────────────────────────────────────────────────────────────

    public static class RuleResult {
        public int score;
        public List<String> triggeredReasons = new ArrayList<>();
        public boolean hasScamKeyword;
        public boolean hasUrgencyKeyword;
        public boolean hasSensitiveKeyword;
        public boolean hasPhishingKeyword;
        public boolean hasFinancialKeyword;
        public boolean hasThreatKeyword;
        public boolean hasApkMention;
    }

    /**
     * Analyze a message with all rule-based detectors.
     * Returns a RuleResult with score and triggered reasons.
     */
    public RuleResult analyze(String message) {
        RuleResult result = new RuleResult();
        if (message == null || message.isBlank()) return result;

        String lower = message.toLowerCase();
        boolean hasUrl = !LinkUtils.extractUrls(message).isEmpty();

        // ── Keyword Matching ─────────────────────────────────────────────────

        // Scam keywords
        List<String> scamMatches = findMatches(lower, SCAM_KEYWORDS);
        if (!scamMatches.isEmpty()) {
            result.hasScamKeyword = true;
            result.score += Math.min(SCAM_KEYWORD_SCORE * scamMatches.size(), 30);
            result.triggeredReasons.add("Scam keywords detected: " + String.join(", ", scamMatches.subList(0, Math.min(2, scamMatches.size()))));
        }

        // Urgency keywords
        List<String> urgencyMatches = findMatches(lower, URGENCY_KEYWORDS);
        if (!urgencyMatches.isEmpty()) {
            result.hasUrgencyKeyword = true;
            result.score += Math.min(URGENCY_KEYWORD_SCORE * urgencyMatches.size(), 25);
            result.triggeredReasons.add("Urgency manipulation detected: " + urgencyMatches.get(0));
        }

        // Sensitive keywords
        List<String> sensitiveMatches = findMatches(lower, SENSITIVE_KEYWORDS);
        if (!sensitiveMatches.isEmpty()) {
            result.hasSensitiveKeyword = true;
            result.score += Math.min(SENSITIVE_KEYWORD_SCORE * sensitiveMatches.size(), 40);
            result.triggeredReasons.add("Sensitive data requested: " + String.join(", ", sensitiveMatches.subList(0, Math.min(2, sensitiveMatches.size()))));
        }

        // Financial keywords
        List<String> financialMatches = findMatches(lower, FINANCIAL_KEYWORDS);
        if (!financialMatches.isEmpty()) {
            result.hasFinancialKeyword = true;
            result.score += Math.min(FINANCIAL_KEYWORD_SCORE * financialMatches.size(), 25);
            result.triggeredReasons.add("Financial fraud pattern: " + financialMatches.get(0));
        }

        // Threat keywords
        List<String> threatMatches = findMatches(lower, THREAT_KEYWORDS);
        if (!threatMatches.isEmpty()) {
            result.hasThreatKeyword = true;
            result.score += Math.min(THREAT_KEYWORD_SCORE * threatMatches.size(), 30);
            result.triggeredReasons.add("Threatening language detected: " + threatMatches.get(0));
        }

        // Phishing keywords
        List<String> phishingMatches = findMatches(lower, PHISHING_KEYWORDS);
        if (!phishingMatches.isEmpty()) {
            result.hasPhishingKeyword = true;
            result.score += Math.min(PHISHING_KEYWORD_SCORE * phishingMatches.size(), 30);
            if (lower.contains("apk")) {
                result.hasApkMention = true;
                result.score += APK_MENTION_SCORE;
                result.triggeredReasons.add("APK file installation requested (very dangerous!)");
            } else {
                result.triggeredReasons.add("Phishing action requested: " + phishingMatches.get(0));
            }
        }

        // ── Pattern Detection ────────────────────────────────────────────────

        if (LinkUtils.containsPhoneNumber(message)) {
            result.score += PHONE_PATTERN_SCORE;
            result.triggeredReasons.add("Unknown phone number embedded in message");
        }

        if (LinkUtils.containsCurrencyPattern(message)) {
            result.score += CURRENCY_PATTERN_SCORE;
            result.triggeredReasons.add("Currency/prize amount mentioned");
        }

        // ALL CAPS check (aggressive messaging style)
        int capsWords = countAllCapsWords(message);
        if (capsWords >= 3) {
            result.score += ALL_CAPS_SCORE;
            result.triggeredReasons.add("Aggressive ALL CAPS text detected");
        }

        // ── Combination Heuristics (bonus score for dangerous combos) ────────

        if (result.hasScamKeyword && result.hasUrgencyKeyword) {
            result.score += SCAM_PLUS_URGENCY_BONUS;
            result.triggeredReasons.add("⚠️ COMBO: Scam + Urgency pattern (classic fraud tactic)");
        }

        if (result.hasSensitiveKeyword && hasUrl) {
            result.score += SENSITIVE_PLUS_LINK_BONUS;
            result.triggeredReasons.add("⚠️ COMBO: Sensitive data + link (phishing attempt likely)");
        }

        if (result.hasThreatKeyword && result.hasUrgencyKeyword) {
            result.score += THREAT_PLUS_URGENCY_BONUS;
            result.triggeredReasons.add("⚠️ COMBO: Threats + Urgency (intimidation tactic)");
        }

        if (result.hasFinancialKeyword && hasUrl) {
            result.score += FINANCIAL_PLUS_LINK_BONUS;
            result.triggeredReasons.add("⚠️ COMBO: Financial scheme + link (investment fraud)");
        }

        // Cap at 100
        result.score = Math.min(result.score, 100);

        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Private Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns which keywords from the list are found in the text.
     */
    private List<String> findMatches(String text, List<String> keywords) {
        List<String> matches = new ArrayList<>();
        for (String kw : keywords) {
            if (text.contains(kw)) {
                matches.add(kw);
            }
        }
        return matches;
    }

    /**
     * Count words that are fully uppercase (length >= 2).
     */
    private int countAllCapsWords(String text) {
        int count = 0;
        for (String word : text.split("\\s+")) {
            String clean = word.replaceAll("[^a-zA-Z]", "");
            if (clean.length() >= 2 && clean.equals(clean.toUpperCase())) {
                count++;
            }
        }
        return count;
    }
}
