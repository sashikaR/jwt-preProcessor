package sr.jmeter.jwt.preprocessor.service.util;

import com.fasterxml.jackson.core.type.TypeReference;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.WeakKeyException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;

import javax.swing.*;

public class JwtUtil {

    private static final Logger log = LogManager.getLogger(JwtUtil.class);

    public static PrivateKey convertPrivateKey(String privateKeyString){
        PrivateKey privateKey = null;
        if(privateKeyString == null || privateKeyString.isEmpty() || privateKeyString.isBlank()){
            log.error("The provided Private Key is not a valid one ...!");
            throw new InputMismatchException("Invalid private key :"+privateKeyString);
        }else {
            // Decode the Base64-encoded private key string
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);

            // Create a KeyFactory instance for the desired algorithm (e.g., RSA)
            KeyFactory keyFactory = null;
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                log.error("Your JDK does not have support for the RSA security algorithm. \n"+e.getMessage());
                throw new RuntimeException(e);
            }

            // Generate a PKCS8EncodedKeySpec object using the decoded private key bytes
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            // Generate the private key using the KeyFactory
            try {
                privateKey = keyFactory.generatePrivate(keySpec);
            } catch (InvalidKeySpecException e) {
                log.error("Private key conversion has failed from provided key String. \n"+e.getMessage());
                throw new RuntimeException(e);
            }
        }
        return privateKey;
    }

    public static RSAPublicKey convertPublicKey(String publicKeyString) {
        // Decode the Base64-encoded public key string
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);

        // Create a KeyFactory instance for RSA
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // Generate an X509EncodedKeySpec object using the decoded public key bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

        // Generate the RSA public key using the KeyFactory
        PublicKey publicKey = null;
        try {
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        // Cast the PublicKey to RSAPublicKey
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

        return rsaPublicKey;
    }

    public static Key convertSecretKey(String secretKey){
        try{
            return Keys.hmacShaKeyFor(secretKey.getBytes());
        }catch(WeakKeyException we){
            log.error("The Provided Key is not a valid key ... "+secretKey+"\n"+ we.getMessage());
            throw new WeakKeyException(Arrays.toString(we.getStackTrace()));
        }
        catch (NullPointerException ne){
            log.error("The Provided Key can not be null ... \n"+ ne.getMessage());
            throw new NullPointerException();
        }
    }

    public static String hashMapToJsonString(HashMap<String, String> map){
        String jsonMap = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            jsonMap= objectMapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            log.error("HashMap to Json String conversion has failed due to "+e.getOriginalMessage());
        }
        return jsonMap;
    }

    public static HashMap<String, String> jsonStringToHashMap(String jsonString) {
        if (jsonString != null && !jsonString.isEmpty()) {
            try {
                ObjectMapper objectMapper = new ObjectMapper();
                return objectMapper.readValue(jsonString, new TypeReference<HashMap<String, String>>() {});
            } catch (JsonProcessingException e) {
                // Handle the exception if needed
                log.error("JSON String to HashMap conversion is failed.. "+e.getOriginalMessage());
                e.printStackTrace();
            } catch (Exception e1){
                log.error("JSON String to HashMap conversion is failed.. "+e1.getMessage());
            }
        }
        log.error("Returning null or empty Map...!");
        return new HashMap<String, String>(); // Return an empty HashMap if the property is not set or empty
    }

    public static Date convertToDateObject(String date){
        if(date != null && !date.equals(JwtProperties.JWT_PAYLOAD_ATTR_DATE_FORMAT_VALUE)){
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern(JwtProperties.JWT_PAYLOAD_ATTR_DATE_FORMAT_VALUE);
            LocalDate dateObj = LocalDate.parse(date, dtf);
            return Date.from(dateObj.atStartOfDay(ZoneId.systemDefault()).toInstant());
        }
        return null;
    }

    public static Map<String,Object> convertMapType(Map<String,String> mapToConvert){
        Map<String,Object> convertedMap = new HashMap<>();
        if(mapToConvert != null){
            for(Map.Entry<String,String> entry : mapToConvert.entrySet()){
                convertedMap.put(entry.getKey(),(Object) entry.getValue());
            }
        }
        return convertedMap;
    }

    /**
     * Convert JTable values into a HashMap
     * JTable should have only two columns (key,value)
     * @param table
     * &#064;HashMap<String,String>
     */
    public static HashMap<String,String> getTableData(JTable table) {
        int rowCount = table.getRowCount();
        HashMap<String,String> keyValueMap = new HashMap<String,String>();
        for(int i=0; i<rowCount; i++){
            String key = String.valueOf(table.getValueAt(i,0));
            String value = String.valueOf(table.getValueAt(i,1));
            keyValueMap.put(key,value);
        }
        log.trace("Converted Map from UI table -- "+keyValueMap);
        return keyValueMap;
    }

    public static HashMap<String,String> filterEmptyRows(HashMap<String,String> tableData){
        HashMap<String,String> filteredData = new HashMap<>();
        for(Map.Entry<String, String> entry : tableData.entrySet()){
            String key = entry.getKey();
            String value = entry.getValue();
            if(key != null && !key.trim().isEmpty()){
                filteredData.put(key, value);
            }
        }
        return filteredData;
    }


}
