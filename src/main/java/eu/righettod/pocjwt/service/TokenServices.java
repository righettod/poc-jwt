package eu.righettod.pocjwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import eu.righettod.pocjwt.crypto.TokenCipher;
import eu.righettod.pocjwt.management.TokenRevoker;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Provides REST stateless services to manage JWT token.
 *
 * @see "https://github.com/auth0/java-jwt"
 * @see "https://jwt.io/introduction"
 */
@Path("/")
public class TokenServices {

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(TokenServices.class);

    /**
     * Accessor for HMAC key - Block serialization and storage as String in JVM memory
     */
    private transient byte[] keyHMAC = null;

    /**
     * Accessor for Ciphering key - Block serialization and storage as String in JVM memory
     */
    private transient byte[] keyCiphering = null;

    /**
     * Accessor for Issuer ID - Block serialization
     */
    private transient String issuerID = null;

    /**
     * Random data generator
     */
    private SecureRandom secureRandom = new SecureRandom();

    /**
     * Handler for token ciphering
     */
    private TokenCipher tokenCipher;

    /**
     * Handler for token revokation
     */
    private TokenRevoker tokenRevoker;

    /**
     * Constructor - Load keys and issuer ID
     *
     * @throws IOException            If any issue occur during keys loading
     * @throws ClassNotFoundException If any issue occur during DB driver loading
     */
    public TokenServices() throws IOException, ClassNotFoundException {
        //Load keys from configuration text files in order to avoid to store keys as String in JVM memory
        this.keyHMAC = Files.readAllBytes(Paths.get("src", "main", "conf", "key-hmac.txt"));
        this.keyCiphering = Files.readAllBytes(Paths.get("src", "main", "conf", "key-ciphering.txt"));

        //Load issuer ID from configuration text file
        this.issuerID = Files.readAllLines(Paths.get("src", "main", "conf", "issuer-id.txt")).get(0);

        //Init token ciphering and revokation handlers
        this.tokenCipher = new TokenCipher();
        this.tokenRevoker = new TokenRevoker();
    }

    /**
     * Authenticate (simulation here) a user based on a login/password couple and return a JWT token
     *
     * @param request  Incoming HTTP request
     * @param response HTTP response sent
     * @param login    User login
     * @param password User password
     * @return A HTTP response containing the JWT token
     */
    @Path("authenticate")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response authenticate(@Context HttpServletRequest request, @Context HttpServletResponse response, @FormParam("login") String login, @FormParam("password") String password) {
        //As it's an authentication simulation we explicitly ignore the password here...
        JSONObject jsonObject = new JSONObject();
        Response r;
        try {
            //Validate the login parameter content to avoid malicious input
            if (Pattern.matches("[a-zA-Z0-9]{1,10}", login)) {
                //Generate a random string that will constitute the fingerprint for this user
                byte[] randomFgp = new byte[50];
                this.secureRandom.nextBytes(randomFgp);
                String userFingerprint = DatatypeConverter.printHexBinary(randomFgp);
                //Add the fingerprint in a hardened cookie - Add cookie manually because SameSite attribute is not supported by javax.servlet.http.Cookie class
                String fingerprintCookie = "__Secure-Fgp=" + userFingerprint + "; SameSite=Strict; HttpOnly; Secure";
                response.addHeader("Set-Cookie", fingerprintCookie);
                //Compute a SHA256 hash of the fingerprint in order to store the fingerprint hash (instead of the raw value) in the token
                //to prevent an XSS to be able to read the fingerprint and set the expected cookie itself
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
                String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);
                //Create the token with a validity of 15 minutes and client context (fingerprint) information
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
                        .withClaim("userFingerprint", userFingerprintHash)
                        .withHeader(headerClaims)
                        .sign(Algorithm.HMAC256(this.keyHMAC));
                //Cipher the token
                String cipheredToken = this.tokenCipher.cipherToken(token, this.keyCiphering);
                //Set token in data container
                jsonObject.put("token", cipheredToken);
                jsonObject.put("status", "Authentication successful !");
            } else {
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
     * Validate the legitimacy of a call with a JWT
     * Normally this code is not a service but it's included in the application as shared function and used by all business services to validate the token
     * before allowing any business processing
     *
     * @param request   Incoming HTTP request
     * @param authToken JWT token
     * @return A HTTP response containing the validity status of the call
     */
    @Path("validate")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response validate(@Context HttpServletRequest request, @HeaderParam("Authorization") String authToken) {
        JSONObject jsonObject = new JSONObject();
        Response r;
        try {
            //Retrieve the token
            String cipheredToken = authToken;
            if (cipheredToken != null) {
                //Remove the "Bearer" string part
                cipheredToken = cipheredToken.split(" ")[1].trim();
            } else {
                throw new SecurityException("Token is mandatory !");
            }

            //Check if the token is not revoked
            if (this.tokenRevoker.isTokenRevoked(cipheredToken)) {
                jsonObject.put("status", "Token already revoked !");
            } else {
                //Retrieve the user fingerprint from the dedicated cookie
                String userFingerprint = null;
                if (request.getCookies() != null && request.getCookies().length > 0) {
                    List<Cookie> cookies = Arrays.stream(request.getCookies()).collect(Collectors.toList());
                    Optional<Cookie> cookie = cookies.stream().filter(c -> "__Secure-Fgp".equals(c.getName())).findFirst();
                    if (cookie.isPresent()) {
                        userFingerprint = cookie.get().getValue();
                    }
                }

                //Validate the userFingerprint and token parameters content to avoid malicious input
                System.out.println("FGP ===>" + userFingerprint);
                if (userFingerprint != null && Pattern.matches("[A-Z0-9]{100}", userFingerprint)) {
                    //Decipher the token
                    String token = this.tokenCipher.decipherToken(cipheredToken, this.keyCiphering);
                    //Compute a SHA256 hash of the received fingerprint in cookie in order to compare to the fingerprint hash stored in the cookie
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
                    String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);
                    //Create a verification context for the token
                    JWTVerifier verifier = JWT.require(Algorithm.HMAC256(this.keyHMAC))
                            .withIssuer(this.issuerID)
                            .withClaim("userFingerprint", userFingerprintHash)
                            .build();
                    //Verify the token
                    DecodedJWT decodedToken = verifier.verify(token);
                    //Set token in data container
                    jsonObject.put("status", "Token OK - Welcome '" + decodedToken.getSubject() + "' !");
                } else {
                    jsonObject.put("status", "Invalid parameter provided !");
                }
            }

            //Build response
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        } catch (JWTVerificationException e) {
            LOG.warn("Verification of the token failed", e);
            //Return info that validation failed
            jsonObject.put("status", "Invalid token !");
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            LOG.warn("Error during token validation", e);
            //Return a generic error message
            jsonObject.put("status", "An error occur !");
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }

        return r;
    }

    /**
     * Revoke the token (logout)
     *
     * @param authToken JWT token
     * @return A HTTP response containing the validity status of the call
     */
    @Path("revoke")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response revoke(@HeaderParam("Authorization") String authToken) {
        JSONObject jsonObject = new JSONObject();
        Response r;
        try {
            //Retrieve the token
            String cipheredToken = authToken;
            if (cipheredToken != null) {
                //Remove the "Bearer" string part
                cipheredToken = cipheredToken.split(" ")[1].trim();
                //Revoke the token
                this.tokenRevoker.revokeToken(cipheredToken);
                jsonObject.put("status", "Token successfully revoked !");
            } else {
                throw new SecurityException("Token is mandatory !");
            }
            //Build response
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            LOG.warn("Error during token validation", e);
            //Return a generic error message
            jsonObject.put("status", "An error occur !");
            r = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }

        return r;
    }


}
