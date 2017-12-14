package org.osivia.jwt.service;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.runtime.model.ComponentContext;
import org.nuxeo.runtime.model.ComponentInstance;
import org.nuxeo.runtime.model.ComponentName;
import org.nuxeo.runtime.model.DefaultComponent;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import net.sf.json.JSONObject;


public class JWTTokenServiceImpl extends DefaultComponent implements JWTTokenService {

    public static final ComponentName ID = new ComponentName("org.osivia.jwt.service.JWTTokenServiceImpl");

    private static final String ALGORITHM_EXTENSION_POINT = "token";

    private static final Log log = LogFactory.getLog(JWTTokenServiceImpl.class);

    /**
     * DEFAULT_VALIDITY
     * 300 seconds
     */
    private static final int DEFAULT_VALIDITY = 300;

    protected final Map<String, TokenDescriptor> algorithmDescriptors;

    public JWTTokenServiceImpl() {
        algorithmDescriptors = new HashMap<>();
    }

    @Override
    public void deactivate(ComponentContext context) throws Exception {
        algorithmDescriptors.clear();
    }

    @Override
    public void registerContribution(Object contribution, String extensionPoint, ComponentInstance contributor) throws Exception {
        if (StringUtils.equals(ALGORITHM_EXTENSION_POINT, extensionPoint)) {
            TokenDescriptor algorithmDescriptor = (TokenDescriptor) contribution;
            String algorithmId = algorithmDescriptor.getId();
            algorithmDescriptors.put(algorithmId, algorithmDescriptor);
            if (log.isDebugEnabled()) {
                log.debug(" Added descriptor : " + algorithmId);
            }
        }
    }

    @Override
    public void unregisterContribution(Object contribution, String extensionPoint, ComponentInstance contributor) throws Exception {
        if (StringUtils.equals(ALGORITHM_EXTENSION_POINT, extensionPoint)) {
            TokenDescriptor algorithmDescriptor = (TokenDescriptor) contribution;
            String algorithmId = algorithmDescriptor.getId();
            algorithmDescriptors.remove(algorithmId);
            if (log.isDebugEnabled()) {
                log.debug(" Removed descriptor : " + algorithmId);
            }
        }
    }


    @Override
    public Map<String, Object> getPayload(String token, String algorithmId) {

        TokenDescriptor algorithmDescriptor = algorithmDescriptors.get(algorithmId);

        Map<String, Object> payload = new HashMap<>();
        if (algorithmDescriptor != null) {
            DecodedJWT jwt = algorithmDescriptor.getJWTVerifier().verify(token);
            Map<String, Claim> claims = jwt.getClaims();
            for (Map.Entry<String, Claim> entry : claims.entrySet()) {
                Claim claim = entry.getValue();
                String key = entry.getKey();
                if (!claim.isNull() && claim.asMap() != null) {
                    payload.put(key, claim.asMap());
                } else if (!claim.isNull()) {
                    payload.put(key, claim.as(Object.class));
                }
            }
        }
        return payload;
    }

    @Override
    public String getSignedToken(String payloadObject, String algorithmId) {

        TokenDescriptor algorithmDescriptor = algorithmDescriptors.get(algorithmId);

        String signedToken = null;

        if (algorithmDescriptor != null) {
            Algorithm algo = algorithmDescriptor.getAlgorithm();
            Map<String, String> headerClaims = new LinkedHashMap<>();
            headerClaims.put(PublicClaims.ALGORITHM, algo.getName());
            headerClaims.put(PublicClaims.TYPE, "JWT");
            String headerJson = JSONObject.fromObject(headerClaims).toString();
            String header = Base64.encodeBase64URLSafeString(headerJson.getBytes(StandardCharsets.UTF_8));
            String payload = Base64.encodeBase64URLSafeString(payloadObject.getBytes(StandardCharsets.UTF_8));
            String content = String.format("%s.%s", header, payload);
            byte[] signatureBytes = algo.sign(content.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.encodeBase64URLSafeString(signatureBytes);
            signedToken = String.format("%s.%s", content, signature);
        }

        return signedToken;
    }

    @Override
    public String getSessionToken(Principal principal, String algorithmId) {
        TokenDescriptor algorithmDescriptor = algorithmDescriptors.get(algorithmId);

        String sessionToken = null;
        if (algorithmDescriptor != null) {
            Calendar cal = GregorianCalendar.getInstance();
            int validity = NumberUtils.toInt(algorithmDescriptor.getDuration(), DEFAULT_VALIDITY);
            cal.add(Calendar.SECOND, validity);
            sessionToken = JWT.create().withIssuedAt(new Date()).withExpiresAt(cal.getTime()).withClaim("userId", principal.getName())
                    .sign(algorithmDescriptor.getAlgorithm());
        }

        return sessionToken;
    }
}
