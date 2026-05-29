package com.substring.auth.repository;

import com.substring.auth.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

	Optional<RefreshToken> findByJti(String jti);

	@Query("select rt from RefreshToken rt join fetch rt.user where rt.jti = :jti")
	Optional<RefreshToken> findByJtiWithUser(@Param("jti") String jti);

}
