package sr.jmeter.jwt.preprocessor.service;

import io.jsonwebtoken.SignatureAlgorithm;

public enum Algorithm {
    HS256(SignatureAlgorithm.HS256),
    RS256(SignatureAlgorithm.RS256),
    NO_SIGN;

    private final SignatureAlgorithm signatureAlgorithm;

    Algorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    Algorithm() {
        this.signatureAlgorithm = null;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public static SignatureAlgorithm mapToSignatureAlgorithm(Algorithm algorithm) {
        switch (algorithm) {
            case HS256:
                return SignatureAlgorithm.HS256;
            case RS256:
                return SignatureAlgorithm.RS256;
            // Handle other cases
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

}
