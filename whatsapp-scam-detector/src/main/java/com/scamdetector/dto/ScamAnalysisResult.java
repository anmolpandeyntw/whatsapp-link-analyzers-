package com.scamdetector.dto;

import lombok.*;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScamAnalysisResult {

    private int riskScore;           // 0-100
    private String riskLevel;        // LOW / MEDIUM / HIGH
    private List<String> reasons;    // list of detected issues
    private String aiInsight;        // AI-generated one-liner
    private int ruleScore;           // score from keyword engine
    private int linkScore;           // score from link analysis
    private boolean containsUrl;
    private boolean containsPhone;
    private List<String> detectedUrls;
    private String aiRiskLevel;      // what AI says
    private int aiConfidence;        // AI confidence %
    private boolean aiAvailable;     // did AI respond?
    private List<String> safetyAdvice; // contextual advice
}
