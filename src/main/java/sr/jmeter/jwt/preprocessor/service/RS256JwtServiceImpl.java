package sr.jmeter.jwt.preprocessor.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;

public class RS256JwtServiceImpl extends BaseJwtServiceImpl{
    Algorithm algorithm = Algorithm.RS256;
    SignatureAlgorithm signatureRS256 = Algorithm.mapToSignatureAlgorithm(algorithm);


    @Override
    public String generateJWT(JwtService jwtServiceObj) {
        return super.generateJWT(jwtServiceObj,signatureRS256);
    }

    @Override
    public Claims getJwtClaims(String jwt, Key publicKey) {
        return  super.getJwtClaims(jwt,algorithm,publicKey);
    }

}
