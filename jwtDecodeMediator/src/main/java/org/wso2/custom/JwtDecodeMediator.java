package org.wso2.custom;

import org.apache.commons.codec.binary.Base64;
import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtDecodeMediator extends AbstractMediator{
    private static final Logger log = LoggerFactory.getLogger(JwtDecodeMediator.class);
    private String jwtHeader;
    private String claimValue;

    private static String retrieveCustomerType(String jwtToken, String claimName) {
        String customerType;

        if(jwtToken!=null){
            String[] split_string = jwtToken.split("\\.");
            if(split_string.length > 2){
                String base64EncodedBody = split_string[1];

                Base64 base64 = new Base64();
                try {
                    String decodedString = new String(base64.decode(base64EncodedBody.getBytes()));
                    JSONParser parser = new JSONParser();
                    JSONObject customerInfoJson = (JSONObject) parser.parse(decodedString);
                    if (customerInfoJson.containsKey(claimName)) {
                        customerType =String.valueOf(customerInfoJson.get(claimName));
                        return customerType;
                    } else {
                        if (log.isDebugEnabled()) {
                            log.error("Customer type is not available" + jwtToken);
                        }
                    }
                } catch (ParseException e) {
                    log.error("Error in parsing user Information " + jwtToken + "\n" + e);
                }
            }else {
                log.error("Invalid JWT Token. JWT does not contain three '.' sections. "  + jwtToken);
            }
        }else{
            log.error("JWT token is null.");
        }
        return null;
    }

    @Override
    public boolean mediate(MessageContext context) {
        String jwtToken=getJWT_HEADER();
        String claimName=getClaimValue();

        String customerType = retrieveCustomerType(jwtToken,claimName);
        if(customerType!=null){
            context.setProperty("customerType", customerType);
            return true;
        }else{
            log.error("Customer type is null");
        }
        return false;
    }

    public String getJWT_HEADER() {
        return jwtHeader;
    }

    public void setJWT_HEADER(String jwtHeader) {
        this.jwtHeader = jwtHeader;
    }

    public String getClaimValue(){
        return claimValue;
    }

    public void setClaimValue(String claimValue){
        this.claimValue =claimValue;
    }
}
