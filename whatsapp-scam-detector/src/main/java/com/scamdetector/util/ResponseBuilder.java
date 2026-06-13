package com.scamdetector.util;

import com.scamdetector.dto.ScamAnalysisResult;
import com.scamdetector.model.Scan;

import java.util.List;
import java.util.Map;

public class ResponseBuilder {

    // ─── Main Analysis Response ───────────────────────────────────────────────

    public static String buildScamAnalysisResponse(ScamAnalysisResult result) {
        StringBuilder sb = new StringBuilder();

        String emoji = getRiskEmoji(result.getRiskLevel());

        // Header
        sb.append(emoji).append(" *Scam Analysis Result*\n");
        sb.append("━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        // Risk
        sb.append("🎯 *Risk Score:* ")
                .append(result.getRiskScore()).append("/100\n");
        sb.append("📊 *Risk Level:* *")
                .append(result.getRiskLevel()).append("*\n\n");

        // Issues — max 3
        if (result.getReasons() != null && !result.getReasons().isEmpty()) {
            sb.append("⚠️ *Why is it risky?*\n");
            result.getReasons().stream().limit(3)
                    .forEach(r -> sb.append("• ").append(r).append("\n"));
            sb.append("\n");
        }

        // AI insight
        if (result.isAiAvailable() && result.getAiInsight() != null) {
            sb.append("*AI says:* ")
                    .append(result.getAiInsight()).append("\n\n");
        }

        // Advice — max 3
        if (result.getSafetyAdvice() != null &&
                !result.getSafetyAdvice().isEmpty()) {
            sb.append("*What to do:*\n");
            result.getSafetyAdvice().stream().limit(3)
                    .forEach(a -> sb.append("✓ ").append(a).append("\n"));
        }

        sb.append("\n━━━━━━━━━━━━━━━━━━━━━━━\n");
        sb.append("Type *help* for commands");

        return sb.toString();
    }

    // ─── Scan Counter ─────────────────────────────────────────────────────────

    public static String buildScanCounterMessage(
            ScamAnalysisResult result, long scanNumber) {
        return buildScamAnalysisResponse(result) +
                "\n_Scan #" + scanNumber + "_";
    }

    // ─── Stats ────────────────────────────────────────────────────────────────

    public static String buildStatsResponse(
            Map<String, Long> stats, long total) {
        long high   = stats.getOrDefault("high", 0L);
        long medium = stats.getOrDefault("medium", 0L);
        long low    = stats.getOrDefault("low", 0L);

        return "*Your Scan Report*\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
                "Total Scans: *" + total + "*\n\n" +
                "HIGH Risk:   *" + high   + "* scams\n" +
                "MEDIUM Risk: *" + medium + "* scams\n" +
                "LOW Risk:    *" + low    + "* safe\n\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━\n" +
                "You have blocked *" + high + "* dangerous scams! 🛡️";
    }

    // ─── History ──────────────────────────────────────────────────────────────

    public static String buildHistoryResponse(List<Scan> scans) {
        if (scans == null || scans.isEmpty()) {
            return "*No scans yet.*\n\n" +
                    "Forward any suspicious message to get started!";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("📋 *Last ").append(scans.size())
                .append(" Scans*\n");
        sb.append("━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        int count = 1;
        for (Scan scan : scans) {
            String emoji = getRiskEmoji(scan.getRiskLevel());
            sb.append(count++).append(". ")
                    .append(emoji).append(" *")
                    .append(scan.getRiskLevel()).append("* — ")
                    .append(scan.getRiskScore()).append("/100\n");

            String preview = scan.getMessage().length() > 50
                    ? scan.getMessage().substring(0, 50) + "..."
                    : scan.getMessage();
            sb.append("   _").append(preview).append("_\n\n");
        }

        sb.append("━━━━━━━━━━━━━━━━━━━━━━━\n");
        sb.append("Forward a message to scan it! 🔍");

        return sb.toString();
    }

    // ─── Help ─────────────────────────────────────────────────────────────────

    public static String buildHelpResponse() {
        return "📖 *Scam Detector — Commands*\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
                "🔍 Forward any message → Instant analysis\n" +
                "📋 *history* → Your last 5 scans\n" +
                "📊 *stats* → Your scan report\n" +
                "🚨 *I clicked the link* → Emergency help\n\n" +
                "📊 *Risk Levels:*\n" +
                "🟢 LOW — Looks safe\n" +
                "🟡 MEDIUM — Be careful\n" +
                "🔴 HIGH — Likely a scam\n\n" +
                "Stay safe! 🛡️";
    }

    // ─── Welcome ──────────────────────────────────────────────────────────────

    public static String buildWelcomeResponse() {
        return "👋 *Welcome to Scam Detector!*\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
                "I analyze suspicious messages and " +
                "protect you from scams.\n\n" +
                "📌 *How to use:*\n" +
                "Simply forward any suspicious message!\n\n" +
                "📱 *Commands:*\n" +
                "• *history* — Last 5 scans\n" +
                "• *stats* — Your report\n" +
                "• *help* — All commands\n\n" +
                "Stay safe! 🛡️";
    }

    // ─── Emergency ────────────────────────────────────────────────────────────

    public static String buildEmergencyResponse() {
        return "🚨 *You clicked a suspicious link!*\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
                "*Act immediately:*\n\n" +
                "1️⃣ Enable *Airplane Mode* right now\n" +
                "2️⃣ Go to Settings → Uninstall unknown apps\n" +
                "3️⃣ Change your *banking & email* passwords\n" +
                "4️⃣ Call your bank to block transactions\n" +
                "5️⃣ Report at *1930* (Cybercrime Helpline)\n\n" +
                "⚠️ *Never share OTP with anyone.*\n\n" +
                "Stay calm and act fast! 🙏";
    }

    // ─── Error ────────────────────────────────────────────────────────────────

    public static String buildErrorResponse() {
        return "❌ Something went wrong.\n" +
                "Please try again in a moment.";
    }

    // ─── TwiML Wrapper ────────────────────────────────────────────────────────

    public static String wrapInTwiml(String messageBody) {
        String escaped = messageBody
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");

        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<Response>\n" +
                "    <Message>\n" +
                "        " + escaped + "\n" +
                "    </Message>\n" +
                "</Response>";
    }

    // ─── Helper ───────────────────────────────────────────────────────────────

    private static String getRiskEmoji(String riskLevel) {
        if (riskLevel == null) return "⚪";
        return switch (riskLevel.toUpperCase()) {
            case "HIGH"   -> "🔴";
            case "MEDIUM" -> "🟡";
            case "LOW"    -> "🟢";
            default       -> "⚪";
        };
    }
}