package sr.jmeter.jwt.preprocessor.service;

import sr.jmeter.jwt.preprocessor.service.util.JwtUtil;
import io.jsonwebtoken.*;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

abstract class BaseJwtServiceImpl implements JwtService {

    private String subject;
    private String id;
    private Date expireTime;
    private Date issueTime;
    private Date notBeforeTime;
    private String issuer;
    private String audience;
    private Key signingKey;
    private  Map<String, String> claimsMap;
    private  Map<String, String> headersMap;
    private static final Logger log = LogManager.getLogger(BaseJwtServiceImpl.class);


    public void setSubject(String subject) {
        this.subject=subject;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    public void setId(String id) {
        this.id=id;
    }
    @Override
    public String getId() {
        return id;
    }

    public void setExpirationTime(Date expirationTime) {
        this.expireTime=expirationTime;
    }
    @Override
    public Date getExpirationTime() {
        return expireTime;
    }

    public void setIssueAtTime(Date issueAtTime) {
        this.issueTime=issueAtTime;
    }
    @Override
    public Date getIssueAtTime() {
        return issueTime;
    }

    public void setNotBeforeTime(Date notBeforeTime) {
        this.notBeforeTime=notBeforeTime;
    }
    @Override
    public Date getNotBeforeTime() {
        return notBeforeTime;
    }

    public void setIssuer(String issuer) {
        this.issuer=issuer;
    }
    @Override
    public String getIssuer() {
        return issuer;
    }

    public void setAudience(String audience) {
        this.audience=audience;
    }
    @Override
    public String getAudience() {
        return audience;
    }

    public void setSigningKey(Key signingKey) {
        this.signingKey=signingKey;
    }
    @Override
    public Key getSigningKey() {
        return signingKey;
    }

    public void setClaims(HashMap<String,String> claims) {
        this.claimsMap = claims;
    }
    @Override
    public Map<String, String> getClaimsMap() {
        return claimsMap;
    }

    public void setHeaders(HashMap<String, String> headers) {
        this.headersMap = headers;
    }

    @Override
    public Map<String, String> getHeadersMap() {
        return headersMap;
    }

    public String generateJWT(JwtService jwtServiceObj, SignatureAlgorithm algorithm) {
        JwtBuilder builder = Jwts.builder()
                .setSubject(jwtServiceObj.getSubject())
                .setAudience(jwtServiceObj.getAudience())
                .setExpiration(jwtServiceObj.getExpirationTime())
                .setIssuer(jwtServiceObj.getIssuer())
                .addClaims(JwtUtil.convertMapType(jwtServiceObj.getClaimsMap()))
                .setHeaderParams(JwtUtil.convertMapType(jwtServiceObj.getHeadersMap()))
                .setId(jwtServiceObj.getId())
                .setNotBefore(jwtServiceObj.getNotBeforeTime());
        if(jwtServiceObj.getSigningKey() != null){
            builder.signWith(jwtServiceObj.getSigningKey(), algorithm);
        }
        log.debug("The JWT Object ... \n"+builder.toString());
        return builder.compact();
    }

    public Claims getJwtClaims(String jwt,Algorithm algorithm, Key signingKey){
        try {
            // Parse the JWT and verify its signature using the provided public key
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(jwt);

            log.info("JWT data is extracted successfully");
            log.debug(claimsJws.getBody());
            return claimsJws.getBody(); // JWT is valid
        } catch (Exception e) {
            // JWT validation failed
            return null;
        }
    }
}
