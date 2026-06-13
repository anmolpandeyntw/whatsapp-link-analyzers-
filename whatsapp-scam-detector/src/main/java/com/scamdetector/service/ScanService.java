package com.scamdetector.service;

import com.scamdetector.dto.ScamAnalysisResult;
import com.scamdetector.model.Scan;
import com.scamdetector.model.User;
import com.scamdetector.repository.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Handles saving scan results and retrieving scan history.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    @Value("${app.max-history-records:5}")
    private int maxHistoryRecords;

    private final ScanRepository scanRepository;

    public ScanService(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    /**
     * Save a scan result to the database.
     */
    @Transactional
    public Scan saveScan(String message, ScamAnalysisResult result, User user) {
        // Combine reasons into a single string
        String reasons = result.getReasons() != null
                ? String.join(" | ", result.getReasons())
                : "None";

        Scan scan = Scan.builder()
                .message(truncate(message, 1000))
                .riskScore(result.getRiskScore())
                .riskLevel(result.getRiskLevel())
                .reason(truncate(reasons, 500))
                .aiInsight(truncate(result.getAiInsight(), 300))
                .ruleScore(result.getRuleScore())
                .linkScore(result.getLinkScore())
                .containsUrl(result.isContainsUrl())
                .user(user)
                .build();

        Scan saved = scanRepository.save(scan);
        log.info("Saved scan id={} for user={}, risk={}", saved.getId(), user.getPhoneNumber(), result.getRiskLevel());
        return saved;
    }

    /**
     * Get last N scans for a user.
     */
    public List<Scan> getRecentScans(User user) {
        return scanRepository.findTopScansByUser(user, PageRequest.of(0, maxHistoryRecords));
    }

    /**
     * Get total scan count for a user.
     */
    public long getTotalScans(User user) {
        return scanRepository.countByUser(user);
    }

    // ─────────────────────────────────────────────────────────────────────────

    private String truncate(String text, int maxLength) {
        if (text == null) return null;
        return text.length() > maxLength ? text.substring(0, maxLength) : text;
    }
}
