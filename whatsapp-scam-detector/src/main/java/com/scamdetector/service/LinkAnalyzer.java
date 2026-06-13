package com.scamdetector.service;

import com.scamdetector.util.LinkUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class LinkAnalyzer {

    private static final Logger log =
            LoggerFactory.getLogger(LinkAnalyzer.class);

    // ─── Score Weights ────────────────────────────────────────────

    private static final int SUSPICIOUS_TLD_SCORE      = 30;
    private static final int AT_SYMBOL_SCORE           = 40;
    private static final int SHORT_LINK_SCORE          = 35;
    private static final int LONG_URL_SCORE            = 15;
    private static final int MANY_SUBDOMAINS_SCORE     = 20;
    private static final int NUMERIC_SPOOFING_SCORE    = 25;
    private static final int BRAND_IMPERSONATION_SCORE = 35;

    // ─── Indirect OTP Keywords ────────────────────────────────────

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
    );

    // ─── Indirect Credential Keywords ────────────────────────────

    private static final List<String> INDIRECT_CREDENTIAL_KEYWORDS =
            List.of(
                    "credential", "login detail",
                    "username and password", "id and password",
                    "account detail", "account information",
                    "personal detail", "personal information",
                    "what i send", "what we sent",
                    "sent to your", "sent to you",
                    "received on your", "you received"
            );

    // ─── Social Engineering Keywords ─────────────────────────────

    private static final List<String> SOCIAL_ENGINEERING_KEYWORDS =
            List.of(
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

    // ─────────────────────────────────────────────────────────────
    //  Result DTO
    // ─────────────────────────────────────────────────────────────

    public static class LinkAnalysisResult {
        public int totalScore;
        public List<String> detectedUrls = new ArrayList<>();
        public List<String> reasons = new ArrayList<>();
        public boolean hasShortLink;
        public boolean hasSuspiciousTld;
        public boolean hasBrandImpersonation;
        public boolean hasPhishingPattern;
    }

    // ─────────────────────────────────────────────────────────────
    //  Main Analysis
    // ─────────────────────────────────────────────────────────────

    public LinkAnalysisResult analyze(String message) {
        LinkAnalysisResult result = new LinkAnalysisResult();

        if (message == null || message.isBlank()) return result;

        String lower = message.toLowerCase();
        int totalScore = 0;

        // ── URL Analysis ──────────────────────────────────────────
        List<String> urls = LinkUtils.extractUrls(message);
        result.detectedUrls = urls;

        if (!urls.isEmpty()) {
            log.info("Found {} URL(s) in message", urls.size());

            for (String url : urls) {
                totalScore += analyzeUrl(url, result);
            }

            if (urls.size() > 1) {
                totalScore += 10;
                result.reasons.add(
                        "Multiple URLs found (" + urls.size() + ")");
            }
        }

        // ── Indirect OTP Detection ────────────────────────────────
        List<String> indirectOtpMatches =
                findMatches(lower, INDIRECT_OTP_KEYWORDS);
        if (!indirectOtpMatches.isEmpty()) {
            totalScore += Math.min(
                    25 * indirectOtpMatches.size(), 50);
            result.reasons.add(
                    "Indirect OTP/code request: "
                            + indirectOtpMatches.get(0));
        }

        // ── Indirect Credential Detection ─────────────────────────
        List<String> credentialMatches =
                findMatches(lower, INDIRECT_CREDENTIAL_KEYWORDS);
        if (!credentialMatches.isEmpty()) {
            totalScore += Math.min(
                    25 * credentialMatches.size(), 50);
            result.reasons.add(
                    "Credential harvesting attempt: "
                            + credentialMatches.get(0));
        }

        // ── Social Engineering Detection ──────────────────────────
        List<String> socialMatches =
                findMatches(lower, SOCIAL_ENGINEERING_KEYWORDS);
        if (!socialMatches.isEmpty()) {
            totalScore += Math.min(
                    20 * socialMatches.size(), 40);
            result.reasons.add(
                    "Social engineering detected: "
                            + socialMatches.get(0));
        }

        // ── Dangerous Combo ───────────────────────────────────────
        if (!socialMatches.isEmpty()
                && !indirectOtpMatches.isEmpty()) {
            totalScore += 25;
            result.reasons.add(
                    "⚠️ COMBO: Social engineering + Code request " +
                            "(account takeover attempt)");
        }

        result.totalScore = Math.min(totalScore, 100);
        return result;
    }

    // ─────────────────────────────────────────────────────────────
    //  Single URL Analysis
    // ─────────────────────────────────────────────────────────────

    private int analyzeUrl(String url, LinkAnalysisResult result) {
        int score = 0;

        // Suspicious TLD
        if (LinkUtils.hasSuspiciousTld(url)) {
            score += SUSPICIOUS_TLD_SCORE;
            result.hasSuspiciousTld = true;
            result.reasons.add(
                    "Suspicious domain extension (.xyz, .tk, .ru)");
        }

        // Short link
        if (LinkUtils.isShortLink(url)) {
            score += SHORT_LINK_SCORE;
            result.hasShortLink = true;
            result.reasons.add(
                    "URL shortener used — hides real destination");
        }

        // @ symbol trick
        if (LinkUtils.hasAtSymbol(url)) {
            score += AT_SYMBOL_SCORE;
            result.hasPhishingPattern = true;
            result.reasons.add(
                    "Phishing trick: @ symbol in URL");
        }

        // Long URL
        if (LinkUtils.isUrlTooLong(url)) {
            score += LONG_URL_SCORE;
            result.reasons.add(
                    "Unusually long URL (" + url.length() + " chars)");
        }

        // Too many subdomains
        int subdomains = LinkUtils.getSubdomainCount(url);
        if (subdomains > 3) {
            score += MANY_SUBDOMAINS_SCORE;
            result.hasPhishingPattern = true;
            result.reasons.add(
                    "Excessive subdomains (" + subdomains + ")");
        }

        // Numeric spoofing
        if (LinkUtils.hasNumericSpoofing(url)) {
            score += NUMERIC_SPOOFING_SCORE;
            result.hasPhishingPattern = true;
            result.reasons.add(
                    "Numeric spoofing detected (e.g. amaz0n.com)");
        }

        // Brand impersonation
        if (LinkUtils.hasBrandImpersonation(url)) {
            score += BRAND_IMPERSONATION_SCORE;
            result.hasBrandImpersonation = true;
            result.reasons.add(
                    "Fake brand domain detected");
        }

        // HTTP not HTTPS
        if (url.startsWith("http://")) {
            score += 5;
            result.reasons.add("Insecure HTTP link");
        }

        return score;
    }

    // ─────────────────────────────────────────────────────────────
    //  Helper
    // ─────────────────────────────────────────────────────────────

    private List<String> findMatches(
            String text, List<String> keywords) {
        List<String> matches = new ArrayList<>();
        for (String kw : keywords) {
            if (text.contains(kw)) {
                matches.add(kw);
            }
        }
        return matches;
    }
}