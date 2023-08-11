package sr.jmeter.jwt.preprocessor.service;

import io.jsonwebtoken.Claims;

import java.security.Key;
import java.util.Date;
import java.util.Map;

public interface JwtService {
    String getSubject();

    String getId();

    Date getExpirationTime();

    Date getIssueAtTime();

    Date getNotBeforeTime();

    String getIssuer();

    String getAudience();

    Key getSigningKey();

    Map<String, String> getClaimsMap();

    Map<String, String> getHeadersMap();

    String generateJWT(JwtService jwtServiceObj);

    Claims getJwtClaims(String jwt, Key signingKey);

}
