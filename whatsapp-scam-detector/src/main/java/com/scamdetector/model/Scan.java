package com.scamdetector.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scans")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "message", columnDefinition = "TEXT", nullable = false)
    private String message;

    @Column(name = "risk_score")
    private Integer riskScore;

    @Column(name = "risk_level", length = 10)
    private String riskLevel;

    @Column(name = "reason", columnDefinition = "TEXT")
    private String reason;

    @Column(name = "ai_insight", columnDefinition = "TEXT")
    private String aiInsight;

    @Column(name = "rule_score")
    private Integer ruleScore;

    @Column(name = "link_score")
    private Integer linkScore;

    @Column(name = "contains_url")
    private Boolean containsUrl;

    @Column(name = "timestamp")
    private LocalDateTime timestamp;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @PrePersist
    protected void onCreate() {
        timestamp = LocalDateTime.now();
    }
}
