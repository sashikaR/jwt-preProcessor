package sr.jmeter.jwt.preprocessor;
import sr.jmeter.jwt.preprocessor.service.HS256JwtServiceImpl;
import sr.jmeter.jwt.preprocessor.service.RS256JwtServiceImpl;
import sr.jmeter.jwt.preprocessor.service.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.junit.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class JwtServiceTest {
    private final String subject = "john.doe@example.com";
    private final String secretKey = "m5yDwbhY70qaj5YXiS55ZSHAllvZGI3od7AvqyVTvCk=";
    private final String audience = "Test World";
    private final static String id = UUID.randomUUID().toString();
    private final String issuer = "Sashika Rangoda";
    private final String rsaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuctR8skrMSGghF65PKB1YA1FpWjEvqncmznV9W9Wz2Y8V+h4VMq6+LbF8Dnl8KedS6KhF0qj69fuQNTDL4Ucsvl+glS5Pfn7WGuDcCRZpT32R+g+IPtwkVIpY/92XMpbVjmFvULM0DZd1SRHMN2uicsqJKaf0lsoGpNH1SAH/2w4s76ULeBivz8DFxl6UDq7IXYnedN8cQNn2uo8VC+hqxVMRlab5bdVzpPWCDY/WmSj/eByixblKRblU5ZhsIjP03znR4UYO0W73955LToUPiZF3TEAZRGI84CxFrTAb1C/5DAyapi2dpvjZxrF5Q88gEiDpAPX/jbMmMJ1zzZU0QIDAQAB";
    private final String rsaPrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5y1HyySsxIaCEXrk8oHVgDUWlaMS+qdybOdX1b1bPZjxX6HhUyrr4tsXwOeXwp51LoqEXSqPr1+5A1MMvhRyy+X6CVLk9+ftYa4NwJFmlPfZH6D4g+3CRUilj/3ZcyltWOYW9QszQNl3VJEcw3a6Jyyokpp/SWygak0fVIAf/bDizvpQt4GK/PwMXGXpQOrshdid503xxA2fa6jxUL6GrFUxGVpvlt1XOk9YINj9aZKP94HKLFuUpFuVTlmGwiM/TfOdHhRg7Rbvf3nktOhQ+JkXdMQBlEYjzgLEWtMBvUL/kMDJqmLZ2m+NnGsXlDzyASIOkA9f+NsyYwnXPNlTRAgMBAAECggEAVQ3hHBY/8aQFSdPbVQfX8/rfcVO/DdHRLjaR3mP0B8ozwcKoo5iTc5yojMrUmxEAj0mKGZGP7T3S0lcUa8KyWrSg16VVkCvKhrXhXAsoBt+QyWZmWs8Av2YvkJm4Y843dgerU/Mqs/7Pge2zsYkqh+Y8Cr9E1xXoDBJ0hfq97o2i0TzNhkMH9lOSffia9v8BUv1453H4fx4/pVoCFLh82br6Ap8MtKj/Y3rr6Qjt6VC5ga4GN58S13mclRZ9MFFl0dir/F6bCuxRuHbrKrBbYUD7v1tbtPkLRHogNQcOCnGNnAQqKE/xLZteC4O/Vrbx7Hu2OOYsw6YRhtWjWdCQKQKBgQDabJQ1/cuMtq84USqUojScngIOT8fdLBItKgH0s/gmB3E3efU/f4Sr765cuJg5X/adidok+ndblZZoNmJiy7uMfVlJpgnBvOSHujbosOkYLEitFAnK7gwzbFaWRbRyWsPN6KK/vXcH/Bzo3h0gMVIKD/3USgGc4QlHXXt9/TxM2wKBgQDZwbdftvIN+s+Td7rFZSvh6fE5QbUz6vdq4zPREL3yKE9RqE/SxKh7yii7/ISfLGRpCY6JuVSdo/u8SOG4bF2IqcGKpSD2vjXRUF02iVvE/E8KN6j7rZ/Ga6j2zF2cNeZrWzlL3X6S1hCiyzCUofRQMFDxJqwWRWCJTXErZZx+wwKBgHiDFdcgO3FczhpVdhfh0wNijqHU1OIr0a+HkOKxdUWOL6I7MNwjAFFZAav40Uw+rTPIfkqOwtIOG5lOAESgQc9Gzb+704BINxLH5EnIaiNDM6oC91A2vRaWPMPWm7PIbmYqZ7lA0O7f5Bd7jThY3fndTuAVIQSsiNEOO/eMg/unAoGBAJ1Kg1WdBU05zTS9OGkbgk4mOPtdzjDZWayYvzYVvM6tdVYLmNUq/nSkezYG2hlL7J++qnorJ8bSy6SelIUtqYZs8INgceYpUSCHxzz8jRBGHCXKPMLHEHE4FQ1oY3nRqUYE1+dH8ATKoaulz8qdDafarqzyfT19EZU8HjH1rMwXAoGAea4AbjOc9pWncuyxKSMyMO99FhGKexSQLMwlc1vHLE/WFKKZMGrK57FsYYINsJq2pEWQqc0zpSri2mQblFBH2Hu8OjvNXnz6qmha0wnVbuSNxr6HPAyjUzMckGwCNxWBzBhqTOWUq8rsBa+8IEjWuv0VXUwbk+2EWtMZh0D00o0=";



    @Test
    public void testJWTServiceObject(){

        Date expireTime = new Date();
        expireTime.setTime(3600000);

        Date ntBeforeTime = new Date();
        ntBeforeTime.setTime(4000000);

        Date issueTime = new Date();
        long currentTime = issueTime.getTime();
        issueTime.setTime(currentTime);

        HashMap<String,String> claims = new HashMap<>();
        claims.put("authorization","read,write");
        claims.put("user-role", "author");

        HashMap<String,String> headers = new HashMap<>();
        claims.put("locale","en");
        claims.put("host-ip", "10.80.68.29");

        // Generate a JwtService Object
        HS256JwtServiceImpl jwtHS256 = new HS256JwtServiceImpl();
        jwtHS256.setAudience(audience);
        jwtHS256.setSigningKey(JwtUtil.convertSecretKey(secretKey));
        jwtHS256.setSubject(subject);
        jwtHS256.setId(id);
        jwtHS256.setClaims(claims);
        jwtHS256.setExpirationTime(expireTime);
        jwtHS256.setIssueAtTime(issueTime);
        jwtHS256.setIssuer(issuer);
        jwtHS256.setNotBeforeTime(ntBeforeTime);
        jwtHS256.setHeaders(headers);

        // validate JwtService Object values
        assertEquals(audience,jwtHS256.getAudience());
        assertEquals(JwtUtil.convertSecretKey(secretKey),jwtHS256.getSigningKey());
        assertEquals(subject,jwtHS256.getSubject());
        assertEquals(id,jwtHS256.getId());
        assertEquals(issuer,jwtHS256.getIssuer());
        assertEquals(expireTime,jwtHS256.getExpirationTime());
        assertEquals(ntBeforeTime,jwtHS256.getNotBeforeTime());
        assertEquals(issueTime,jwtHS256.getIssueAtTime());
        assertEquals("read,write",jwtHS256.getClaimsMap().get("authorization"));
        assertEquals("author",jwtHS256.getClaimsMap().get("user-role"));
        assertEquals("en",jwtHS256.getClaimsMap().get("locale"));
        assertEquals("10.80.68.29",jwtHS256.getClaimsMap().get("host-ip"));
    }

    @Test
    public void testHS256JwtGeneration(){

        HashMap<String,String> claims = new HashMap<>();
        claims.put("authorization","read,write");
        claims.put("user-role", "author");

        // Generate a JwtService Object
        HS256JwtServiceImpl jwtHS256 = new HS256JwtServiceImpl();
        jwtHS256.setAudience(audience);
        jwtHS256.setSigningKey(JwtUtil.convertSecretKey(secretKey));
        jwtHS256.setSubject(subject);
        jwtHS256.setId(id);
        jwtHS256.setIssuer(issuer);
        jwtHS256.setClaims(claims);
        String jwt = jwtHS256.generateJWT(jwtHS256);

        // Get JWT data
        Claims actualJwtData = jwtHS256.getJwtClaims(jwt,JwtUtil.convertSecretKey(secretKey));

        assertEquals(audience,actualJwtData.getAudience());
        assertEquals(subject,actualJwtData.getSubject());
        assertEquals(id,actualJwtData.getId());
        assertEquals(issuer,actualJwtData.getIssuer());
        assertEquals("read,write",actualJwtData.get("authorization"));
        assertEquals("author",actualJwtData.get("user-role"));
    }

    @Test
    public void testRS256JwtGeneration(){

        HashMap<String,String> claims = new HashMap<>();
        claims.put("authorization","read,write");
        claims.put("user-role", "author");

        // Generate a JwtService Object
        RS256JwtServiceImpl jwtRS256 = new RS256JwtServiceImpl();
        jwtRS256.setAudience(audience);
        jwtRS256.setSigningKey(JwtUtil.convertPrivateKey(rsaPrivateKey));
        jwtRS256.setSubject(subject);
        jwtRS256.setId(id);
        jwtRS256.setIssuer(issuer);
        jwtRS256.setClaims(claims);
        String jwt = jwtRS256.generateJWT(jwtRS256);

        // Get JWT data
        Claims actualJwtData = jwtRS256.getJwtClaims(jwt,JwtUtil.convertPublicKey(rsaPublicKey));

        assertEquals(audience,actualJwtData.getAudience());
        assertEquals(subject,actualJwtData.getSubject());
        assertEquals(id,actualJwtData.getId());
        assertEquals(issuer,actualJwtData.getIssuer());
        assertEquals("read,write",actualJwtData.get("authorization"));
        assertEquals("author",actualJwtData.get("user-role"));
    }

}
