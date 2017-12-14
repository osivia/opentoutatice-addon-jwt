package org.osivia.jwt.automation;

import java.security.Principal;

import org.nuxeo.ecm.automation.core.annotations.Context;
import org.nuxeo.ecm.automation.core.annotations.Operation;
import org.nuxeo.ecm.automation.core.annotations.OperationMethod;
import org.nuxeo.ecm.automation.core.annotations.Param;
import org.nuxeo.ecm.core.api.Blob;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.impl.blob.StringBlob;
import org.nuxeo.runtime.api.Framework;
import org.osivia.jwt.service.JWTTokenService;

import net.sf.json.JSONObject;

@Operation(id = GetJWTToken.ID, category = "Users & Groups", label = "Gets the authenticated user token", description = "Gets the authenticated user token",
addToStudio = false)
public class GetJWTToken {

    public final static String ID = "UserGroup.GetJWTToken";

    private JWTTokenService jWTTokenService;

    @Param(name = "algorithmId", required = true)
    private String algorithmId;

    /**
     * Session.
     */
    @Context
    protected CoreSession coreSession;

    @OperationMethod
    public Blob run() throws ClientException {

        JSONObject jsonResponse = new JSONObject();

        String sessionToken = "";

        Principal principal = coreSession.getPrincipal();

        if (principal != null) {
            sessionToken = getJWTTokenService().getSessionToken(principal, algorithmId);
        }

        jsonResponse.element("token", sessionToken);

        return new StringBlob(jsonResponse.toString(), "application/json");
    }

    private JWTTokenService getJWTTokenService()
    {
        if (jWTTokenService == null) {
            jWTTokenService = Framework.getService(JWTTokenService.class);
        }

        return jWTTokenService;
    }
}
