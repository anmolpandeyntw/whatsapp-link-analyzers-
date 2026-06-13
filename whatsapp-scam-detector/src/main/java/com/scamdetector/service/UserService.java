package com.scamdetector.service;

import com.scamdetector.model.User;
import com.scamdetector.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Manages user creation and retrieval.
 * Each unique phone number is treated as a separate user.
 */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Get existing user or create new one for the given phone number.
     */
    @Transactional
    public User getOrCreateUser(String phoneNumber) {
        return userRepository.findByPhoneNumber(phoneNumber)
                .orElseGet(() -> {
                    log.info("Creating new user for phone: {}", phoneNumber);
                    User newUser = User.builder()
                            .phoneNumber(phoneNumber)
                            .totalScans(0)
                            .build();
                    return userRepository.save(newUser);
                });
    }

    /**
     * Increment scan count for a user.
     */
    @Transactional
    public void incrementScanCount(User user) {
        user.setTotalScans(user.getTotalScans() + 1);
        userRepository.save(user);
    }

    /**
     * Check if this is a new user (first time messaging).
     */
    public boolean isNewUser(String phoneNumber) {
        return !userRepository.existsByPhoneNumber(phoneNumber);
    }
}
