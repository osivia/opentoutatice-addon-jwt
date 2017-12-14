package org.osivia.jwt.service;

import java.security.Principal;
import java.util.Map;

public interface JWTTokenService {

    Map<String, Object> getPayload(String token, String algorithmId);

    String getSignedToken(String payloadObject, String algorithmId);

    String getSessionToken(Principal principal, String algorithmId);

}
