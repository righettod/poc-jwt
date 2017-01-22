package eu.righettod.pocjwt.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

/**
 * Handle ciphering and deciphering of the token using AES-GCM.
 * Use a DB in order to link a GCM NONCE to a ciphered message and ensure that a NONCE is never reused
 * and also allow use of several application nodes in load balancing.
 * Here we use H2 with a direct connection but on real app, connection will be managed using a pool in app server.
 *
 * @see "https://www.cryptologie.net/article/361/nonce-disrespecting-adversaries-practical-forgery-attacks-on-gcm-in-tls/"
 * @see "https://en.wikipedia.org/wiki/Galois/Counter_Mode"
 * @see "https://gist.github.com/praseodym/f2499b3e14d872fe5b4a"
 * @see "https://www.cigital.com/blog/proper-use-of-javas-securerandom/"
 * @see "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl"
 * @see "https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html#updateAAD-byte:A-"
 * @see "https://tools.ietf.org/html/rfc5084"
 * @see "http://stackoverflow.com/a/30468962"
 */
public class TokenCipher {

    /** AES-GCM parameters */
    private static final int GCM_NONCE_LENGTH = 12; // in bytes

    /** AES-GCM parameters */
    private static final int GCM_TAG_LENGTH = 16; // in bytes

    /**Secure random generator */
    private final SecureRandom secRandom = new SecureRandom();

    /** JDBC URL of the DB*/
    private final String jdbcUrl = "jdbc:h2:file:" + new File("target/store").getAbsolutePath() + ";INIT=RUNSCRIPT FROM 'classpath:db_creation.sql';DB_CLOSE_ON_EXIT=TRUE;";

    /**
     * Constructor - Load DB Driver
     * @throws ClassNotFoundException If any issue occur during DB driver loading
     */
    public TokenCipher() throws ClassNotFoundException {
        //FIXME: I use this way for the POC because I cannot achieve
        // to make the Datasource injection using @Resource run with the embedded Tomcat.
        Class.forName("org.h2.Driver");
    }

    /**
     * Cipher a JWT
     * @param jwt Token to cipher
     * @param key Ciphering key
     * @return The ciphered version of the token encoded in HEX
     * @throws Exception If any issue occur during token ciphering operation
     */
    public String cipherToken(String jwt, byte[] key) throws Exception {
        //Verify parameters
        if(jwt == null || jwt.isEmpty() || key == null || key.length == 0){
            throw new IllegalArgumentException("Both parameters must be specified !");
        }

        //Generate a NONCE
        //NOTE: As in the DB, the column to store the NONCE is flagged UNIQUE then the insert will fail
        //if the NONCE already exists, normally as we use the Java Secure Random implementation
        // it will never happen
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        secRandom.nextBytes(nonce);

        //Prepare ciphering key from bytes provided
        SecretKey aesKey = new SecretKeySpec(key, 0, key.length, "AES");

        //Setup Cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        //Add "Additional Authentication Data" (AAD) in order to operate in AEAD mode - Generate it
        byte[] aad = new byte[32];
        secRandom.nextBytes(aad);
        cipher.updateAAD(aad);

        //Cipher the token
        byte[] cipheredToken = cipher.doFinal(jwt.getBytes("utf-8"));

        //Compute a SHA256 of the ciphered token
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] cipheredTokenDigest = digest.digest(cipheredToken);

        //Store GCM NONCE and GCM AAD
        this.storeNonceAndAAD(DatatypeConverter.printHexBinary(nonce), DatatypeConverter.printHexBinary(aad), DatatypeConverter.printHexBinary(cipheredTokenDigest));

        return DatatypeConverter.printHexBinary(cipheredToken);
    }

    /**
     * Decipher a JWT
     * @param jwtInHex Token to decipher encoded in HEX
     * @param key Ciphering key
     * @return The token in clear text
     * @throws Exception If any issue occur during token deciphering operation
     */
    public String decipherToken(String jwtInHex, byte[] key) throws Exception{
        //Verify parameters
        if(jwtInHex == null || jwtInHex.isEmpty() || key == null || key.length == 0){
            throw new IllegalArgumentException("Both parameters must be specified !");
        }

        //Decode the ciphered token
        byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

        //Compute a SHA256 of the ciphered token
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] cipheredTokenDigest = digest.digest(cipheredToken);

        //Read the GCM NONCE and GCM AAD associated from the DB
        Map<String,String> gcmInfos = this.readNonceAndAAD(DatatypeConverter.printHexBinary(cipheredTokenDigest));
        if(gcmInfos == null){
            throw new Exception("Cannot found a NONCE and AAD associated to the token provided !");
        }
        byte[] nonce = DatatypeConverter.parseHexBinary(gcmInfos.get("NONCE"));
        byte[] aad = DatatypeConverter.parseHexBinary(gcmInfos.get("AAD"));

        //Prepare ciphering key from bytes provided
        SecretKey aesKey = new SecretKeySpec(key, 0, key.length, "AES");

        //Setup Cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        //Add "Additional Authentication Data" (AAD) in order to operate in AEAD mode
        cipher.updateAAD(aad);

        //Decipher the token
        byte[] decipheredToken = cipher.doFinal(cipheredToken);

        return new String(decipheredToken);
    }


    /**
     * Store GCM NONCE and GCM AAD in the DB
     * @param nonceInHex Nonce encoded in HEX
     * @param aadInHex AAD encoded in HEX
     * @param jwtTokenDigestInHex SHA256 of the JWT ciphered token encoded in HEX
     * @throws Exception If any issue occur during communication with DB
     */
    private void storeNonceAndAAD(String nonceInHex, String aadInHex, String jwtTokenDigestInHex) throws Exception {
        try (Connection con = DriverManager.getConnection(jdbcUrl)) {
            String query = "insert into nonce(jwt_token_digest, gcm_nonce, gcm_aad) values(?, ?, ?)";
            int insertedRecordCount;
            try (PreparedStatement pStatement = con.prepareStatement(query)) {
                pStatement.setString(1, jwtTokenDigestInHex);
                pStatement.setString(2, nonceInHex);
                pStatement.setString(3, aadInHex);
                insertedRecordCount = pStatement.executeUpdate();
            }
            if (insertedRecordCount != 1) {
                throw new IllegalStateException("Number of inserted record is invalid, 1 expected but is " + insertedRecordCount);
            }
        }
    }

    /**
     * Read GCM NONCE and GCM AAD from the DB
     * @param jwtTokenDigestInHex SHA256 of the JWT ciphered token encoded in HEX for which we must read the NONCE and AAD
     * @return A dict containing the NONCE and AAD if they exists for the specified token
     * @throws Exception If any issue occur during communication with DB
     */
    private  Map<String,String> readNonceAndAAD(String jwtTokenDigestInHex) throws Exception{
        Map<String,String> gcmInfos = null;
        try (Connection con = DriverManager.getConnection(jdbcUrl)) {
            String query = "select gcm_nonce, gcm_aad from nonce where jwt_token_digest = ?";
            try (PreparedStatement pStatement = con.prepareStatement(query)) {
                pStatement.setString(1, jwtTokenDigestInHex);
                try (ResultSet rSet = pStatement.executeQuery()) {
                    while (rSet.next()) {
                        gcmInfos = new HashMap<>(2);
                        gcmInfos.put("NONCE", rSet.getString(1));
                        gcmInfos.put("AAD", rSet.getString(2));
                    }
                }
            }
        }

        return gcmInfos;
    }

}
