package sr.jmeter.jwt.preprocessor;

import sr.jmeter.jwt.preprocessor.service.util.JwtUtil;
import org.apache.jmeter.processor.PreProcessor;
import org.apache.jmeter.testelement.AbstractTestElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.util.Strings;

import java.util.HashMap;


public class JwtPreProcessor extends AbstractTestElement implements PreProcessor {

    private static final String SECRET_KEY_PROPERTY = "JWT.secretKey";
    private static final String ALGORITHM_PROPERTY = "JWT.algorithm";
    private static final String JTABLE_JWT_HEADER_PROPERTY = "JWT.headerTable";
    private static final String JTABLE_JWT_PAYLOAD_PROPERTY = "JWT.payloadTable";
    private static final String JTABLE_JWT_CLAIMS_PROPERTY = "JWT.claimsTable";
    private static final String VARIABLE_NAME_TOUSE_PROPERTY = "JWT.varNameToUse";
    private static final Logger log = LogManager.getLogger(JwtPreProcessor.class);

    private String algorithm;
    private HashMap<String,String> jwtHeaderData;
    private  HashMap<String,String> jwtPayloadData;
    private  HashMap<String,String> jwtClaimsData;
    private String variableNameToUse;

    public JwtPreProcessor() {
    }

    @Override
    public void process() {

        log.trace("---- Values in JwtPreProcessor");
        log.trace("** Secret Key -----"+getSecretKey());
        log.trace("** Algorithm Selected -----"+ getAlgorithm());
        log.trace("** JWT Headers-----"+ getJwtHeaderData());
        log.trace("** JWT Payload-----"+ getJwtPayloadData());
        log.trace("** JWT Claims-----"+ getJwtClaimsData());
        log.trace("** Variable Name To Use-----"+ getVariableNameToUse());
        JwtServiceWrapper jwtServiceWrapper = new JwtServiceWrapper();
        jwtServiceWrapper.generateJwt(getSecretKey(),getAlgorithm(),getJwtHeaderData(),
                getJwtPayloadData(),getJwtClaimsData(),getVariableNameToUse());
    }

    public void setSecretKey(String secretKeyValue){
        setProperty(SECRET_KEY_PROPERTY,secretKeyValue);
    }

    public String getSecretKey(){
        return getPropertyAsString(SECRET_KEY_PROPERTY, Strings.EMPTY);
    }

    public void setAlgorithm(String algorithm){
        setProperty(ALGORITHM_PROPERTY,algorithm);
    }

    public String getAlgorithm(){
        return getPropertyAsString(ALGORITHM_PROPERTY, Strings.EMPTY);
    }

    public void setJwtHeaderData(HashMap<String,String> jwtHeaderData){
        String jwtHeaderJson = JwtUtil.hashMapToJsonString(jwtHeaderData);
        setProperty(JTABLE_JWT_HEADER_PROPERTY, jwtHeaderJson);
    }

    public HashMap<String,String> getJwtHeaderData(){
        String jwtHeaderData = getPropertyAsString(JTABLE_JWT_HEADER_PROPERTY, Strings.EMPTY);
        return JwtUtil.jsonStringToHashMap(jwtHeaderData);
    }

    public void setJwtPayloadData(HashMap<String,String> jwtPayloadData){
        String jwtHeaderJson = JwtUtil.hashMapToJsonString(jwtPayloadData);
        setProperty(JTABLE_JWT_PAYLOAD_PROPERTY, jwtHeaderJson);
    }

    public HashMap<String,String> getJwtPayloadData(){
        String jwtPayloadData = getPropertyAsString(JTABLE_JWT_PAYLOAD_PROPERTY, Strings.EMPTY);
        return JwtUtil.jsonStringToHashMap(jwtPayloadData);
    }

    public void setJwtClaimsData(HashMap<String,String> jwtClaimsData){
        String jwtClaimsJson = JwtUtil.hashMapToJsonString(jwtClaimsData);
        setProperty(JTABLE_JWT_CLAIMS_PROPERTY, jwtClaimsJson);
    }

    public HashMap<String,String> getJwtClaimsData(){
        String jwtClaimsData = getPropertyAsString(JTABLE_JWT_CLAIMS_PROPERTY, Strings.EMPTY);
        return JwtUtil.jsonStringToHashMap(jwtClaimsData);
    }

    public void setVariableNameToUse(String variableNameToUse){
        setProperty(VARIABLE_NAME_TOUSE_PROPERTY,variableNameToUse);
    }

    public String getVariableNameToUse(){
        return getPropertyAsString(VARIABLE_NAME_TOUSE_PROPERTY, Strings.EMPTY);
    }
}
