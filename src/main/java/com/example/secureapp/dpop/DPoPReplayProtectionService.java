package com.example.secureapp.dpop;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * DPoP Replay Protection Service.
 *
 * <p>Prevents replay attacks by tracking JWT IDs (jti) that have already been
 * used. Each jti is stored in a time-limited Caffeine cache. If the same jti
 * is presented within the TTL window the request is rejected.</p>
 *
 * <p><b>Production note:</b> For a multi-instance deployment replace the
 * in-memory Caffeine cache with a Redis-backed store using the same API
 * (e.g. {@code SETNX} with a TTL matching {@link DPoPConstants#JTI_CACHE_TTL_SECONDS}).
 * </p>
 */
@Service
public class DPoPReplayProtectionService {

    private static final Logger logger = LoggerFactory.getLogger(DPoPReplayProtectionService.class);

    /**
     * Cache of seen jti values. The value is simply {@link Boolean#TRUE} —
     * we only care about the key's presence.
     */
    private final Cache<String, Boolean> jtiCache;

    public DPoPReplayProtectionService() {
        this.jtiCache = Caffeine.newBuilder()
                .maximumSize(DPoPConstants.JTI_CACHE_MAX_SIZE)
                .expireAfterWrite(Duration.ofSeconds(DPoPConstants.JTI_CACHE_TTL_SECONDS))
                .build();
    }

    /**
     * Checks whether the given jti has already been used. If not, the jti is
     * recorded and future calls with the same value will return {@code false}.
     *
     * @param jti the JWT ID claim value
     * @return {@code true} if the jti is fresh (first use); {@code false} if it
     *         has been seen before (replay detected)
     */
    public boolean isJtiUnique(String jti) {
        if (jti == null || jti.isBlank()) {
            logger.warn("DPoP replay check: jti is null or blank — rejecting");
            return false;
        }

        Boolean existing = jtiCache.getIfPresent(jti);
        if (existing != null) {
            logger.warn("DPoP replay detected: jti [{}] has already been used", jti);
            return false;
        }

        jtiCache.put(jti, Boolean.TRUE);
        logger.debug("DPoP jti [{}] accepted and cached for replay protection", jti);
        return true;
    }
}
