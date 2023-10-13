package sr.jmeter.jwt.preprocessor.service.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.WeakKeyException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;

import javax.swing.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class JwtUtil {

    private static final Logger log = LogManager.getLogger(JwtUtil.class);

    public static PrivateKey convertPrivateKey(String privateKeyString){
        PrivateKey privateKey = null;
        if(privateKeyString == null || privateKeyString.isEmpty() || privateKeyString.isBlank()){
            log.error("The provided Private Key is not a valid one ...!");
            throw new InputMismatchException("Invalid private key :"+privateKeyString);
        }else {
            // Remove the PEM header and footer and newline characters
            String rsaPrivateKeyPem = privateKeyString
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\n", "");

            // Base64 decode the private key
            byte[] privateKeyBytes = Base64.decode(rsaPrivateKeyPem);

            // Create a PKCS8EncodedKeySpec from the bytes
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            // Get the private key
            try{
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                privateKey = keyFactory.generatePrivate(keySpec);
            } catch (NoSuchAlgorithmException e) {
                log.error("The provided Private Key is not a valid RSA private key ...!");
                log.error(e.getMessage());
                throw new RuntimeException(e);
            } catch (InvalidKeySpecException e) {
                log.error("The provided Private Key is not a valid one ...!");
                log.error(e.getMessage());
                throw new RuntimeException(e);
            }
        }
        return privateKey;
    }

    public static PublicKey convertPublicKey(String publicKeyString) {
        PublicKey publicKey = null;
        // Remove the PEM header and footer and newline characters
        String rsaPublicKeyPem = publicKeyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\n", "");

        // Base64 decode the private key
        byte[] publicKeyBytes = Base64.decode(rsaPublicKeyPem);

        // Create a X509EncodedKeySpec from the bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

        // Get the private key
        try{
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            log.error("The provided Private Key is not a valid RSA public key ...!");
            log.error(e.getMessage());
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            log.error("The provided Public Key is not a valid one ...!");
            log.error(e.getMessage());
            throw new RuntimeException(e);
        }
        return publicKey;
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
