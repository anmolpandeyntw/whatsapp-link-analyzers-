package com.scamdetector.util;

import java.net.URI;
import java.util.*;
import java.util.regex.*;

/**
 * Utility class for URL extraction and preliminary analysis.
 */
public class LinkUtils {

    // ─── Regex Patterns ────────────────────────────────────────────────────────

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://[\\w\\-]+(\\.[\\w\\-]+)+(/[\\w\\-./?%&=+#@!~]*)?)",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "(\\+?\\d[\\d\\s\\-]{8,}\\d)"
    );

    private static final Pattern CURRENCY_PATTERN = Pattern.compile(
            "(₹|rs\\.?|inr|\\$|usd|prize|reward|cash|win|lakh|crore)",
            Pattern.CASE_INSENSITIVE
    );

    // ─── Known URL Shorteners ──────────────────────────────────────────────────

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "goo.gl", "t.co",
            "ow.ly", "is.gd", "buff.ly", "adf.ly",
            "short.ly", "rb.gy", "cutt.ly", "shorturl.at"
    );

    // ─── Suspicious TLDs ───────────────────────────────────────────────────────

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            ".xyz", ".tk", ".ml", ".ga", ".cf", ".ru",
            ".top", ".click", ".download", ".review",
            ".win", ".loan", ".men", ".work", ".date"
    );

    // ─── Trusted Banking / Brand Domains (for spoofing check) ─────────────────

    private static final Set<String> TRUSTED_BRANDS = Set.of(
            "paytm", "phonepe", "googlepay", "amazon", "flipkart",
            "sbi", "hdfc", "icici", "axis", "kotak",
            "npci", "upi", "irctc", "uidai", "incometax"
    );

    // ─── Numeric Substitution Patterns ────────────────────────────────────────

    private static final Map<String, String> LEET_MAP = Map.of(
            "0", "o", "1", "i", "3", "e", "4", "a", "5", "s"
    );

    // ──────────────────────────────────────────────────────────────────────────
    //  Public Methods
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Extract all HTTP/HTTPS URLs from a text message.
     */
    public static List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        if (text == null || text.isBlank()) return urls;

        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            urls.add(matcher.group(1));
        }
        return urls;
    }

    /**
     * Check if text contains a phone number.
     */
    public static boolean containsPhoneNumber(String text) {
        if (text == null) return false;
        return PHONE_PATTERN.matcher(text).find();
    }

    /**
     * Check if text contains currency or prize-related patterns.
     */
    public static boolean containsCurrencyPattern(String text) {
        if (text == null) return false;
        return CURRENCY_PATTERN.matcher(text).find();
    }

    /**
     * Check if a URL is a known link shortener.
     */
    public static boolean isShortLink(String url) {
        String lower = url.toLowerCase();
        return SHORTENERS.stream().anyMatch(lower::contains);
    }

    /**
     * Check if the URL's TLD is suspicious.
     */
    public static boolean hasSuspiciousTld(String url) {
        String lower = url.toLowerCase();
        return SUSPICIOUS_TLDS.stream().anyMatch(lower::contains);
    }

    /**
     * Check if the URL contains an @ symbol (classic phishing trick to hide real domain).
     * e.g. https://bank.com@evil.com/login
     */
    public static boolean hasAtSymbol(String url) {
        try {
            URI uri = new URI(url);
            return uri.getUserInfo() != null;
        } catch (Exception e) {
            return url.contains("@");
        }
    }

    /**
     * Count subdomains. More than 2 subdomain levels is suspicious.
     * e.g. login.secure.bank.evil.com
     */
    public static int getSubdomainCount(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) return 0;
            return host.split("\\.").length - 1;
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Check if the domain impersonates a trusted brand using numeric substitutions.
     * e.g. amaz0n.com, g00gle.com
     */
    public static boolean hasNumericSpoofing(String url) {
        String lower = url.toLowerCase();

        // Normalize leet speak to letters
        String normalized = lower;
        for (Map.Entry<String, String> entry : LEET_MAP.entrySet()) {
            normalized = normalized.replace(entry.getKey(), entry.getValue());
        }

        // Check if normalized version contains a trusted brand name
        // but original URL has numbers mixed in
        for (String brand : TRUSTED_BRANDS) {
            if (normalized.contains(brand) && !lower.contains(brand)) {
                return true; // original had leet, normalized matches brand
            }
        }
        return false;
    }

    /**
     * Check if domain looks like it's impersonating a trusted brand
     * with extra words (paytm-secure-login.xyz, sbi-update-kyc.com).
     */
    public static boolean hasBrandImpersonation(String url) {
        String lower = url.toLowerCase();
        for (String brand : TRUSTED_BRANDS) {
            if (lower.contains(brand)) {
                // If it also contains suspicious keywords → impersonation
                String[] suspiciousAddons = {"secure", "login", "verify", "update",
                        "kyc", "reward", "prize", "free", "win", "offer", "claim"};
                for (String addon : suspiciousAddons) {
                    if (lower.contains(addon)) return true;
                }
            }
        }
        return false;
    }

    /**
     * Extract the domain from a URL.
     */
    public static String extractDomain(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            return host != null ? host : url;
        } catch (Exception e) {
            return url;
        }
    }

    /**
     * Check if URL is unusually long (> 75 chars is suspicious).
     */
    public static boolean isUrlTooLong(String url) {
        return url.length() > 75;
    }
}
