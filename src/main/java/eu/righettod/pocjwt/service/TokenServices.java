package eu.righettod.pocjwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import eu.righettod.pocjwt.crypto.TokenCipher;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Provides REST stateless services to manage JWT token.
 * @see "https://github.com/auth0/java-jwt"
 * @see "https://jwt.io/introduction"
 */
@Path("/")
public class TokenServices {

    /** Logger */
    private static final Logger LOG = LoggerFactory.getLogger(TokenServices.class);

    /**Accessor for HMAC and Ciphering keys - Block serialization and storage as String in JVM memory*/
    private transient byte[] keyHMAC = null;

    /**Accessor for HMAC and Ciphering keys - Block serialization and storage as String in JVM memory*/
    private transient byte[] keyCiphering = null;

    /**Accessor for Issuer ID - Block serialization*/
    private transient String issuerID = null;

    /** Handler for token ciphering */
    private TokenCipher tokenCipher;

    /**
     * Constructor - Load keys and issuer ID
     * @throws IOException If any issue occur during keys loading
     * @throws ClassNotFoundException If any issue occur during DB driver loading
     */
    public TokenServices() throws IOException, ClassNotFoundException {
        //Load keys from configuration text files in order to avoid to store keys as String in JVM memory
        this.keyHMAC = Files.readAllBytes(Paths.get("src","main","conf","key-hmac.txt"));
        this.keyCiphering = Files.readAllBytes(Paths.get("src","main","conf","key-ciphering.txt"));

        //Load issuer ID from configuration text files
        this.issuerID = Files.readAllLines(Paths.get("src","main","conf","issuer-id.txt")).get(0);

        //Init token ciphering handler
        this.tokenCipher = new TokenCipher();
    }

    /**
     * Authenticate (simulation here) a user based on a login/password couple and return a JWT token
     * @param request Incoming HTTP request
     * @param login User login
     * @param password User password
     * @param browserFingerprintDigest SHA256 digest of the user browser fingerprint encoded in HEX
     * @return A HTTP response containing the JWT token
     */
    @Path("authenticate")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response authenticate(@Context HttpServletRequest request, @FormParam("login") String login, @FormParam("password") String password, @FormParam("browserFingerprintDigest") String browserFingerprintDigest){
        //As it's an authentication simulation we explicitly ignore the password here...
        JSONObject jsonObject = new JSONObject();
        Response r;
        try{
            //Validate the login and the browserFingerprintDigest parameters content to avoid malicious input
            if(Pattern.matches("[a-zA-Z0-9]{1,10}", login) && Pattern.matches("[a-z0-9]{64}", browserFingerprintDigest)){
                //Create the token with a validity of 15 minutes and client context (IP + Browser fingerprint digest) information
                Calendar c = Calendar.getInstance();
                Date now = c.getTime();
                c.add(Calendar.MINUTE, 15);
                Date expirationDate = c.getTime();
                Map<String, Object> headerClaims = new HashMap<>();
                headerClaims.put("typ", "JWT");
                String token = JWT.create().withSubject(login)
                                       .withExpiresAt(expirationDate)
                                       .withIssuer(this.issuerID)
                                       .withIssuedAt(now)
                                       .withNotBefore(now)
                                       .withClaim("clientIP", this.retrieveClientIP(request))
                                       .withClaim("browserFingerprintDigest", browserFingerprintDigest)
                                       .withHeader(headerClaims)
                                       .sign(Algorithm.HMAC256(this.keyHMAC));
                //Cipher the token
                String cipheredToken = this.tokenCipher.cipherToken(token, this.keyCiphering);
                //Set token in data container
                jsonObject.put("token", cipheredToken);
                jsonObject.put("status", "Authentication successful !");
            }else{
                jsonObject.put("token", "-");
                jsonObject.put("status", "Invalid parameter provided !");
            }

            //Build response
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            LOG.error("Error during authentication", e);
            //Return a generic error message
            jsonObject.put("token", "-");
            jsonObject.put("status", "An error occur !");
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }

        return r;
    }


    /**
     * Validate the legitimacy of a call with a JWT.
     * Normally this code is not a service but it's included in the application as shared function and used by all business services to validate the token
     * before allowing any business processing
     * @param request Incoming HTTP request
     * @param browserFingerprintDigest SHA256 digest of the user browser fingerprint encoded in HEX
     * @return A HTTP response containing the validity status of the call
     */
    @Path("validate")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response validate(@Context HttpServletRequest request, @FormParam("browserFingerprintDigest") String browserFingerprintDigest){
        //As it's an authentication simulation we explicitly ignore the password here...
        JSONObject jsonObject = new JSONObject();
        Response r;
        try{
            //Retrieve the token
            String cipheredToken = request.getHeader("Authorization");
            if(cipheredToken != null){
                //Remove the "Bearer" string part
                cipheredToken = cipheredToken.split(" ")[1].trim();
            }

            //Validate the browserFingerprintDigest and token parameters content to avoid malicious input
            if(Pattern.matches("[a-z0-9]{64}", browserFingerprintDigest) && cipheredToken != null){
                //Decipher the token
                String token = this.tokenCipher.decipherToken(cipheredToken,this.keyCiphering);
                //Create a verification context for the token
                JWTVerifier verifier = JWT.require(Algorithm.HMAC256(this.keyHMAC))
                                               .withIssuer(this.issuerID)
                                               .withClaim("clientIP", this.retrieveClientIP(request))
                                               .withClaim("browserFingerprintDigest", browserFingerprintDigest)
                                               .build();
                //Verify the token
                DecodedJWT decodedToken = verifier.verify(token);
                //Set token in data container
                jsonObject.put("status", "Token OK - Welcome '" + decodedToken.getSubject() + "' !");
            }else{
                jsonObject.put("status", "Invalid parameter provided !");
            }

            //Build response
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }
        catch (JWTVerificationException e) {
            LOG.warn("Verification of the token failed", e);
            //Return a generic error message
            jsonObject.put("status", "Invalid token !");
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }
        catch (Exception e) {
            LOG.warn("Error during token validation", e);
            //Return a generic error message
            jsonObject.put("status", "An error occur !");
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }

        return r;
    }

    /**
     * Return the client IP address
     * @param request Incoming HTTP request
     * @return The client IP address
     * @throws IllegalArgumentException If the IP retrieved is invalid
     * @see "https://en.wikipedia.org/wiki/X-Forwarded-For"
     */
    private String retrieveClientIP(HttpServletRequest request) throws IllegalArgumentException{
        String address;
        //Get IP from X-Forwarded-For header or from the request object directly
        String ip = request.getHeader("X-Forwarded-For");
        if(ip != null){
            if(ip.contains(",")){
                ip = ip.split(",")[0];
            }
            address = ip.trim();
        }else{
            address = request.getRemoteAddr();
        }
        //Validate IP format
        if(!InetAddressValidator.getInstance().isValid(address)){
            throw new IllegalArgumentException("Invalid IP address !");
        }

        return address;
    }
}
