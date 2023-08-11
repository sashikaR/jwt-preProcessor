package sr.jmeter.jwt.preprocessor.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;

public class HS256JwtServiceImpl extends BaseJwtServiceImpl{

    Algorithm algorithm = Algorithm.HS256;
    SignatureAlgorithm signatureHS256Algo = Algorithm.mapToSignatureAlgorithm(algorithm);


    @Override
    public String generateJWT(JwtService jwtService) {
        return super.generateJWT(jwtService,signatureHS256Algo);
    }

    @Override
    public Claims getJwtClaims(String jwt, Key signingKey) {
        return  super.getJwtClaims(jwt,algorithm,signingKey);
    }



}
