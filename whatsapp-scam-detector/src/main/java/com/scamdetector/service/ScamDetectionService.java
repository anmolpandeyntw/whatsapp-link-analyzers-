package com.scamdetector.service;

import com.scamdetector.dto.ScamAnalysisResult;
import com.scamdetector.service.GeminiAIService.AIResult;
import com.scamdetector.service.LinkAnalyzer.LinkAnalysisResult;
import com.scamdetector.service.RuleBasedDetector.RuleResult;
import com.scamdetector.util.LinkUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Main Scam Detection Orchestrator.
 *
 * Combines:
 * 1. Rule-Based Detector (keywords + patterns)
 * 2. Link Analysis Engine (URL multi-layer check)
 * 3. Google Gemini AI (classification + reason)
 * 4. Safety Advisor (contextual advice)
 *
 * Final Decision Engine merges all scores into a unified risk assessment.
 */
@Service
public class ScamDetectionService {

    private static final Logger log = LoggerFactory.getLogger(ScamDetectionService.class);

    private final RuleBasedDetector ruleBasedDetector;
    private final LinkAnalyzer linkAnalyzer;
    private final GeminiAIService geminiAIService;
    private final SafetyAdvisor safetyAdvisor;

    public ScamDetectionService(
            RuleBasedDetector ruleBasedDetector,
            LinkAnalyzer linkAnalyzer,
            GeminiAIService geminiAIService,
            SafetyAdvisor safetyAdvisor
    ) {
        this.ruleBasedDetector = ruleBasedDetector;
        this.linkAnalyzer = linkAnalyzer;
        this.geminiAIService = geminiAIService;
        this.safetyAdvisor = safetyAdvisor;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Main Entry Point
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Perform full multi-layer scam analysis on a message.
     */
    public ScamAnalysisResult analyze(String message) {
        log.info("Starting scam analysis for message (length={})", message.length());

        // ── Layer 1: Rule-Based Analysis ─────────────────────────────────────
        RuleResult ruleResult = ruleBasedDetector.analyze(message);
        log.info("Rule score: {}", ruleResult.score);

        // ── Layer 2: Link Analysis ───────────────────────────────────────────
        LinkAnalysisResult linkResult = linkAnalyzer.analyze(message);
        log.info("Link score: {}", linkResult.totalScore);

        // ── Layer 3: AI Analysis (with fallback) ─────────────────────────────
        AIResult aiResult = geminiAIService.analyzeMessage(message);
        log.info("AI result: {} ({}%): {}", aiResult.riskLevel, aiResult.confidence, aiResult.reason);

        // ── Layer 4: Final Decision Engine ───────────────────────────────────
        int finalScore = computeFinalScore(ruleResult.score, linkResult.totalScore, aiResult);
        String finalRiskLevel = computeRiskLevel(finalScore);

        // ── Compile All Reasons ───────────────────────────────────────────────
        List<String> allReasons = new ArrayList<>();
        allReasons.addAll(ruleResult.triggeredReasons);
        allReasons.addAll(linkResult.reasons);

        // ── Safety Advice ─────────────────────────────────────────────────────
        List<String> advice = safetyAdvisor.generateAdvice(ruleResult, linkResult, finalRiskLevel);

        // ── Build Result ──────────────────────────────────────────────────────
        return ScamAnalysisResult.builder()
                .riskScore(finalScore)
                .riskLevel(finalRiskLevel)
                .reasons(allReasons)
                .aiInsight(aiResult.reason)
                .aiRiskLevel(aiResult.riskLevel)
                .aiConfidence(aiResult.confidence)
                .aiAvailable(aiResult.success)
                .ruleScore(ruleResult.score)
                .linkScore(linkResult.totalScore)
                .containsUrl(!linkResult.detectedUrls.isEmpty())
                .containsPhone(LinkUtils.containsPhoneNumber(message))
                .detectedUrls(linkResult.detectedUrls)
                .safetyAdvice(advice)
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Final Decision Engine
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Weighted combination of all analysis layers.
     *
     * Weights:
     * - Rule-based score: 40%
     * - Link score:       35%
     * - AI score:         25%
     */
    private int computeFinalScore(int ruleScore, int linkScore, AIResult aiResult) {
        // Convert AI risk level to a numeric score
        int aiScore = convertAiToScore(aiResult);

        if (aiResult.success) {
            // Full weighted combination
            double weighted = (ruleScore * 0.40)
                            + (linkScore * 0.35)
                            + (aiScore   * 0.25);
            return (int) Math.min(Math.round(weighted), 100);
        } else {
            // AI failed → weight between rule and link only
            double weighted = (ruleScore * 0.55)
                            + (linkScore * 0.45);
            return (int) Math.min(Math.round(weighted), 100);
        }
    }

    /**
     * Convert AI classification to numeric score considering confidence.
     */
    private int convertAiToScore(AIResult aiResult) {
        if (!aiResult.success) return 0;

        int baseScore = switch (aiResult.riskLevel) {
            case "HIGH"   -> 85;
            case "MEDIUM" -> 50;
            case "LOW"    -> 15;
            default       -> 30;
        };

        // Adjust by confidence (confidence acts as a multiplier)
        double confidenceMultiplier = aiResult.confidence / 100.0;
        return (int) Math.round(baseScore * (0.5 + 0.5 * confidenceMultiplier));
    }

    /**
     * Map numeric score to risk level.
     */
    private String computeRiskLevel(int score) {
        if (score >= 71) return "HIGH";
        if (score >= 41) return "MEDIUM";
        return "LOW";
    }
}
