package com.scamdetector.service;

import com.scamdetector.dto.ScamAnalysisResult;
import com.scamdetector.service.RuleBasedDetector.RuleResult;
import com.scamdetector.service.LinkAnalyzer.LinkAnalysisResult;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Generates contextual safety advice based on what was detected in the message.
 */
@Component
public class SafetyAdvisor {

    /**
     * Build a targeted list of advice based on analysis results.
     */
    public List<String> generateAdvice(
            RuleResult ruleResult,
            LinkAnalysisResult linkResult,
            String riskLevel
    ) {
        List<String> advice = new ArrayList<>();

        // Link-specific advice
        if (!linkResult.detectedUrls.isEmpty()) {
            advice.add("Do NOT click any links in this message");
            if (linkResult.hasShortLink) {
                advice.add("Short links hide the real destination — always avoid them");
            }
            if (linkResult.hasBrandImpersonation) {
                advice.add("This link pretends to be a trusted brand — it is fake");
            }
        }

        // OTP / sensitive data advice
        if (ruleResult.hasSensitiveKeyword) {
            advice.add("NEVER share OTP, PIN, or password with anyone");
            advice.add("Real banks/companies NEVER ask for your OTP via WhatsApp");
        }

        // APK installation advice
        if (ruleResult.hasApkMention) {
            advice.add("Do NOT install any APK files from unknown sources — they contain malware");
            advice.add("Only install apps from Google Play Store / Apple App Store");
        }

        // Prize / lottery advice
        if (ruleResult.hasScamKeyword) {
            advice.add("No legitimate lottery or prize requires payment or personal info upfront");
            advice.add("If it sounds too good to be true, it is a scam");
        }

        // Financial scheme advice
        if (ruleResult.hasFinancialKeyword) {
            advice.add("Be very cautious of investment schemes promising guaranteed profits");
            advice.add("Never send money to unknown accounts");
        }

        // Threat / intimidation advice
        if (ruleResult.hasThreatKeyword) {
            advice.add("Scammers use fake threats to scare you — stay calm and verify");
            advice.add("Real government/legal notices are NEVER sent via WhatsApp");
        }

        // General advice for high risk
        if ("HIGH".equals(riskLevel)) {
            advice.add("Block this number immediately");
            advice.add("Report to National Cybercrime Helpline: 1930");
        }

        // Default minimum advice
        if (advice.isEmpty()) {
            advice.add("Be cautious with messages from unknown numbers");
            advice.add("Verify any claims through official channels before acting");
        }

        return advice;
    }

    /**
     * Detect and return emergency-level advice if user indicates they clicked.
     */
    public boolean isEmergencyMessage(String message) {
        if (message == null) return false;
        String lower = message.toLowerCase();
        return lower.contains("i clicked") ||
               lower.contains("maine click kiya") ||
               lower.contains("i opened the link") ||
               lower.contains("clicked the link") ||
               lower.contains("i installed") ||
               lower.contains("link click") ||
               lower.contains("apk install");
    }

    /**
     * Detect if user is asking for history.
     */
    public boolean isHistoryRequest(String message) {
        if (message == null) return false;
        String lower = message.toLowerCase().trim();
        return lower.equals("history") ||
               lower.equals("my history") ||
               lower.equals("past scans") ||
               lower.equals("show history");
    }

    /**
     * Detect if user is asking for help.
     */
    public boolean isHelpRequest(String message) {
        if (message == null) return false;
        String lower = message.toLowerCase().trim();
        return lower.equals("help") ||
               lower.equals("hi") ||
               lower.equals("hello") ||
               lower.equals("start") ||
               lower.equals("commands");
    }
}
