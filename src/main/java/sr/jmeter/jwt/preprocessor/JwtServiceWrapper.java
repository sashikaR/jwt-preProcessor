package sr.jmeter.jwt.preprocessor;

import sr.jmeter.jwt.preprocessor.service.Algorithm;
import sr.jmeter.jwt.preprocessor.service.HS256JwtServiceImpl;
import sr.jmeter.jwt.preprocessor.service.RS256JwtServiceImpl;
import sr.jmeter.jwt.preprocessor.service.util.JwtUtil;
import org.apache.jmeter.threads.JMeterContextService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sr.jmeter.jwt.preprocessor.service.util.JwtProperties;

import java.security.Key;
import java.util.HashMap;

import static sr.jmeter.jwt.preprocessor.service.util.JwtProperties.JWT_PAYLOAD_DEFAULT_ATTR_VALUE;

public class JwtServiceWrapper {

    private static final Logger log = LogManager.getLogger(JwtServiceWrapper.class);

    public void generateJwt(String secretKey, String algorithm, HashMap<String,String> jwtHeader,
                            HashMap<String,String> jwtPayload, HashMap<String,String> jwtClaims,String jmeterVariableName){

        String jwt ="";
        if(algorithm.equals(Algorithm.HS256.toString())){
            // Generate JWT with HS256 sign
            jwt = generateHS256signToken(JwtUtil.convertSecretKey(secretKey),jwtHeader,jwtPayload,jwtClaims);
        }else if(algorithm.equals(Algorithm.RS256.toString())){
            // Generate JWT with RS256 sign
            jwt = generateRS256signToken(JwtUtil.convertPrivateKey(secretKey),jwtHeader,jwtPayload,jwtClaims);
        }else if(algorithm.equals(Algorithm.NO_SIGN.toString())){
            // Generate JWT with-out signing
            jwt = generateHS256signToken(null,jwtHeader,jwtPayload,jwtClaims);
        }else {
            log.fatal("The selected algorithm does not supported by the plugin. - "+algorithm);
        }
        log.debug("************** JWT Is Generated ****************************");
        log.debug(jwt);
        log.debug("*********************** END ********************************");
        saveJwtInJmeterVariable(jwt,jmeterVariableName);
    }

    private void saveJwtInJmeterVariable(String jwt, String variableName){
        JMeterContextService.getContext().getVariables().put(variableName, jwt);
        log.info("JWT is successfully saved in - "+variableName);
    }

    private String generateHS256signToken(Key key, HashMap<String,String> jwtHeadersMap,
                                          HashMap<String,String> jwtPayloadMap, HashMap<String,String> jwtClaimsMap){

        // Generate a JwtService Object
        HS256JwtServiceImpl jwtHS256 = new HS256JwtServiceImpl();

        // set jwt headers
        if(jwtHeadersMap !=null && !jwtHeadersMap.isEmpty()){
            jwtHS256.setHeaders(jwtHeadersMap);
        }
        // set jwt payload values
        if(!jwtPayloadMap.get(JwtProperties.JWT_ATTR_AUDIENCE).equals(JWT_PAYLOAD_DEFAULT_ATTR_VALUE)){
            jwtHS256.setAudience(jwtPayloadMap.get(JwtProperties.JWT_ATTR_AUDIENCE));
        }
        jwtHS256.setSigningKey(key);
        if(jwtPayloadMap.get(JwtProperties.JWT_ATTR_SUBJECT).equals(JWT_PAYLOAD_DEFAULT_ATTR_VALUE)){
            jwtHS256.setSubject(jwtPayloadMap.get(JwtProperties.JWT_ATTR_SUBJECT));
        }
        if(!jwtPayloadMap.get(JwtProperties.JWT_ATTR_ID).equals(JWT_PAYLOAD_DEFAULT_ATTR_VALUE)){
            jwtHS256.setId(jwtPayloadMap.get(JwtProperties.JWT_ATTR_ID));
        }
        if(!jwtPayloadMap.get(JwtProperties.JWT_ATTR_ISSUER).equals(JWT_PAYLOAD_DEFAULT_ATTR_VALUE)){
            jwtHS256.setIssuer(jwtPayloadMap.get(JwtProperties.JWT_ATTR_ISSUER));
        }
        jwtHS256.setExpirationTime(JwtUtil.convertToDateObject(jwtPayloadMap.get(JwtProperties.JWT_ATTR_EXPIRE_TIME)));
        jwtHS256.setNotBeforeTime(JwtUtil.convertToDateObject(jwtPayloadMap.get(JwtProperties.JWT_ATTR_NOT_BEFORE_TIME)));
        jwtHS256.setIssueAtTime(JwtUtil.convertToDateObject(jwtPayloadMap.get(JwtProperties.JWT_ATTR_ISSUE_TIME)));
        // set jwt headers
        if(jwtClaimsMap !=null && !jwtClaimsMap.isEmpty()){
            jwtHS256.setClaims(jwtClaimsMap);
        }else {
            jwtHS256.setClaims(null);
        }
        return jwtHS256.generateJWT(jwtHS256);
    }

    private String generateRS256signToken(Key key, HashMap<String,String> jwtHeadersMap,
                                          HashMap<String,String> jwtPayloadMap, HashMap<String,String> jwtClaimsMap){

        // Generate a JwtService Object
        RS256JwtServiceImpl jwtRS256 = new RS256JwtServiceImpl();

        // set jwt headers
        if(jwtHeadersMap !=null && !jwtHeadersMap.isEmpty()){
            jwtRS256.setHeaders(jwtHeadersMap);
        }
        // set jwt payload values
        if(!jwtPayloadMap.get(JwtProperties.JWT_ATTR_AUDIENCE).equals(JWT_PAYLOAD_DEFAULT_ATTR_VALUE)){
            jwtRS256.setAudience(jwtPayloadMap.get(JwtProperties.JWT_ATTR_AUDIENCE));
        }
        jwtRS256.setSigningKey(key);
        if(!jwtPayloadMap.get(JwtProperties.JWT_ATTR_SUBJECT).equals(JWT_PAYLOAD_DEFAULT_ATTR_VALUE)){
            jwtRS256.setSubject(jwtPayloadMap.get(JwtProperties.JWT_ATTR_SUBJECT));
        }
        if(!jwtPayloadMap.get(JwtProperties.JWT_ATTR_ID).equals(JWT_PAYLOAD_DEFAULT_ATTR_VALUE)){
            jwtRS256.setId(jwtPayloadMap.get(JwtProperties.JWT_ATTR_ID));
        }
        if(!jwtPayloadMap.get(JwtProperties.JWT_ATTR_ISSUER).equals(JWT_PAYLOAD_DEFAULT_ATTR_VALUE)){
            jwtRS256.setIssuer(jwtPayloadMap.get(JwtProperties.JWT_ATTR_ISSUER));
        }
        jwtRS256.setExpirationTime(JwtUtil.convertToDateObject(jwtPayloadMap.get(JwtProperties.JWT_ATTR_EXPIRE_TIME)));
        jwtRS256.setNotBeforeTime(JwtUtil.convertToDateObject(jwtPayloadMap.get(JwtProperties.JWT_ATTR_NOT_BEFORE_TIME)));
        jwtRS256.setIssueAtTime(JwtUtil.convertToDateObject(jwtPayloadMap.get(JwtProperties.JWT_ATTR_ISSUE_TIME)));
        // set jwt headers
        if(jwtClaimsMap !=null && !jwtClaimsMap.isEmpty()){
            jwtRS256.setClaims(jwtClaimsMap);
        }else {
            jwtRS256.setClaims(null);
        }
        return jwtRS256.generateJWT(jwtRS256);
    }
}
