package com.scamdetector;

import com.scamdetector.dto.ScamAnalysisResult;
import com.scamdetector.service.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
class ScamDetectionServiceTest {

    @Autowired
    private ScamDetectionService scamDetectionService;

    @Test
    void testHighRiskScamMessage() {
        String scamMsg = "URGENT! You have WON ₹50,000 lottery prize! " +
                         "Click http://bit.ly/claim-now to claim. " +
                         "Enter your OTP and bank details. Act NOW!";

        ScamAnalysisResult result = scamDetectionService.analyze(scamMsg);

        assertNotNull(result);
        assertTrue(result.getRiskScore() >= 70, "Expected HIGH risk score, got: " + result.getRiskScore());
        assertEquals("HIGH", result.getRiskLevel());
        assertFalse(result.getReasons().isEmpty());
        assertTrue(result.isContainsUrl());
    }

    @Test
    void testLowRiskNormalMessage() {
        String normalMsg = "Hey, are you coming to the meeting at 3pm tomorrow?";

        ScamAnalysisResult result = scamDetectionService.analyze(normalMsg);

        assertNotNull(result);
        assertTrue(result.getRiskScore() <= 40, "Expected LOW risk score, got: " + result.getRiskScore());
        assertEquals("LOW", result.getRiskLevel());
    }

    @Test
    void testSuspiciousLinkMessage() {
        String linkMsg = "Check this deal: http://paytm-secure-login.xyz/verify?id=123456";

        ScamAnalysisResult result = scamDetectionService.analyze(linkMsg);

        assertNotNull(result);
        assertTrue(result.getRiskScore() >= 40);
        assertTrue(result.isContainsUrl());
        assertTrue(result.getLinkScore() > 0);
    }

    @Test
    void testOtpPhishingMessage() {
        String otpMsg = "Dear customer, your account will be blocked. " +
                        "Please share your OTP and KYC details immediately.";

        ScamAnalysisResult result = scamDetectionService.analyze(otpMsg);

        assertNotNull(result);
        assertTrue(result.getRiskScore() >= 50);
        assertFalse(result.getReasons().isEmpty());
    }

    @Test
    void testRuleBasedDetectorInIsolation() {
        RuleBasedDetector detector = new RuleBasedDetector();

        RuleBasedDetector.RuleResult result = detector.analyze(
                "Congratulations! You have won a prize. Act now, limited time offer!"
        );

        assertTrue(result.score > 0);
        assertTrue(result.hasScamKeyword);
        assertTrue(result.hasUrgencyKeyword);
        assertFalse(result.triggeredReasons.isEmpty());
    }

    @Test
    void testLinkAnalyzerInIsolation() {
        LinkAnalyzer analyzer = new LinkAnalyzer();

        LinkAnalyzer.LinkAnalysisResult result = analyzer.analyze(
                "Visit http://bit.ly/fakelink to claim your reward"
        );

        assertTrue(result.totalScore > 0);
        assertTrue(result.hasShortLink);
        assertEquals(1, result.detectedUrls.size());
    }
}
