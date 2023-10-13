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
    private final String rsaPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkgFrwT6c4UrxIPgA0MSs\n" +
            "k6hZLVBLkeJ3xn/h4D4EondIvXJJgjPPRWsa1mQMcs1ScTuTNuzZk02CN4VjyFrj\n" +
            "dTFif9JGOmJqFLB0fr52BJGAl+bnIMyY68AGHSfRQM9tfmXLFfucu3JIzRC7zVWx\n" +
            "OH/xW+RJIkRFXlk6ORYvyZin/3QH8BhPi3CsCnAyEhiXePSKQ2Ml1xIs2SRrymxB\n" +
            "OUeQiS+UqIdZGXjaAUF5/XRd4+9FeYXUs2+0Ev0LAnxIFZY0k5B7y2m/pfIL3xzx\n" +
            "DFvIP1avfVLnFu9fUcrD8SEuJOJFnt6UMa0kqJPRFRYxtz8FN8vYaJ9PlU1Wg8FK\n" +
            "9wIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    private String rsaPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
        "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCSAWvBPpzhSvEg\n" +
        "+ADQxKyTqFktUEuR4nfGf+HgPgSid0i9ckmCM89FaxrWZAxyzVJxO5M27NmTTYI3\n" +
        "hWPIWuN1MWJ/0kY6YmoUsHR+vnYEkYCX5ucgzJjrwAYdJ9FAz21+ZcsV+5y7ckjN\n" +
        "ELvNVbE4f/Fb5EkiREVeWTo5Fi/JmKf/dAfwGE+LcKwKcDISGJd49IpDYyXXEizZ\n" +
        "JGvKbEE5R5CJL5Soh1kZeNoBQXn9dF3j70V5hdSzb7QS/QsCfEgVljSTkHvLab+l\n" +
        "8gvfHPEMW8g/Vq99UucW719RysPxIS4k4kWe3pQxrSSok9EVFjG3PwU3y9hon0+V\n" +
        "TVaDwUr3AgMBAAECggEAfgGb7XsMCaOT1tAyY/pYtlZkICdcENtSY42act0TQuOP\n" +
        "c3Be4G+2QkLdNonB9JIexHqV4qEmZWpPJ3uHUjKee1XTnFztHxYwVwqyf3AAipDI\n" +
        "WlB8yGHK2CsxG5hxj211IdDYJHCyI1POYKxAaEW8XPaOZq/uLhSdiX+YMAxl0aUO\n" +
        "ELo/7QHH6cg/oLUQ/I8BLk+doF6ORS3pCtsyj/P2arZJ8dG6QC8jV/FJ1Gzqov2C\n" +
        "89YKdQVdMCjTWTx7W3K7lwAAa7P0QRGwm62S0WzQSDOCPM18qJWQPVe8rggq6geS\n" +
        "93WHJ27dLKXfvPgpTNCJ0IqdxV0DilY4EUFo6JutgQKBgQDYHJ3yToc9+vQOhm/M\n" +
        "w9P/Cm1nziFHBd8jTa3zsUSV+A/omUUG8OsFPzmWZI+E87bFAd6BY2nXnxsSfYqv\n" +
        "k6C7FRj5kKJ5XXbDploLjh2v8hGzh+u+G3tD5f/fY6XI/Q3aC42qtt9mjVOSHGo0\n" +
        "c8Ly9RKHzFqk5joYAboz3HwaxQKBgQCs9EBkY8krukWI1fVO2T1KmAUpVn8kihn9\n" +
        "DJDp49NFutLBdtoPVobytQDCPxmFJtDn9UnEZfzpNjH/yofFtS9OrYRwVL42nuCV\n" +
        "Gngk0edrvA43Qj7emSj/AT96HFNcM6XYVv4ku5OwKSblTyZ4Lloq1qXxlE9XZU+y\n" +
        "p4T3vHfaiwKBgQCahEuCFheofyfEwuZo15NaBRCYac9tQot6aG35kUNinsxxGDU8\n" +
        "c0D2rW/1Uc0z2DVTwrReesAQhRgMLmrcgocnfDwxI/KnJ+ZkmSpEnMYpKMDzRjmN\n" +
        "4YRO1cIO7OZ6QESJJD2UU9CDOIUKMPrWqfY3VHZ9VeVxhZL/2yxRLFInqQKBgQCU\n" +
        "JbCWjWb/XtI7ENLMlIbMw4UAUMgdu3HhcQccYXtSamInN7A3nS2A7oxU1wn8JTCi\n" +
        "0Fg8tAO8nCCd85TzRGzeXwFn2x8H2HWVIpQxLd+mR/KBYOxLbjRQongGGAdLni38\n" +
        "LyAIxOgP6GAZ4f+YyFOSCEUitqBzwyNOa/IY5sZfWwKBgQCuw5yv3MQ/7Kh4IEDi\n" +
        "mNEd8DR0ypLGGNHl0ocxtBKAwm/Hkygktk78+ynaHxuYsi+pKPhno0zG/hsMgdRN\n" +
        "rwFLRihGG09dft+6lZ/Plaip4E+uv3HGQgW1S78PQjjDBi4MkZObUFgo5yUds3eC\n" +
        "cJjjvTGc3rxNf7XgJ11nh0fzBg==\n" +
        "-----END PRIVATE KEY-----";


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
