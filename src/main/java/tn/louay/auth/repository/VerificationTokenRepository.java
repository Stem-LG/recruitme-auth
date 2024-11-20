package tn.louay.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import tn.louay.auth.entities.VerificationToken;

public interface VerificationTokenRepository extends
        JpaRepository<VerificationToken, Long> {
    VerificationToken findByToken(String token);
}
