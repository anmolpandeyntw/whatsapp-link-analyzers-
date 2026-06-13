package com.scamdetector.repository;

import com.scamdetector.model.Scan;
import com.scamdetector.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {

    List<Scan> findByUserOrderByTimestampDesc(User user);

    @Query("SELECT s FROM Scan s WHERE s.user = :user ORDER BY s.timestamp DESC")
    List<Scan> findTopScansByUser(@Param("user") User user,
                                  org.springframework.data.domain.Pageable pageable);

    long countByUser(User user);

    @Query("SELECT s FROM Scan s WHERE s.user = :user AND s.riskLevel = :level ORDER BY s.timestamp DESC")
    List<Scan> findByUserAndRiskLevel(@Param("user") User user, @Param("level") String level);
}
