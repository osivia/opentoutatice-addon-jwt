package org.osivia.jwt.authentication;

import java.util.List;
import java.util.Map;

import javax.security.auth.spi.LoginModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;
import org.osivia.jwt.service.JWTTokenService;

/**
 * Handles authentication with a JWT token sent as a request header or request parameter.
 * <p>
 * The user is retrieved with the {@link JWTTokenService}.
 * <p>
 * This Authentication Plugin is configured to be used with the Trusting_LM {@link LoginModule} plugin => no password
 * check will be done, a principal will be created from the userName if the user exists in the user directory.
 *
 */
public class JWTTokenAuthenticator implements NuxeoAuthenticationPlugin {

    private static final String ALLOW_ANONYMOUS_KEY = "allowAnonymous";

    private static final String ALGORITHM_ID_KEY = "algorithmId";

    private static final Log log = LogFactory.getLog(JWTTokenAuthenticator.class);

    protected static final String TOKEN_HEADER = "Authorization";

    protected static final String TOKEN_PARAM = "token";

    private static final String TOKEN_PREFIX = "Bearer";

    protected String algorithmId;

    protected boolean allowAnonymous = false;

    private JWTTokenService jWTTokenService;

    @Override
    public Boolean handleLoginPrompt(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String baseURL) {
        return false;
    }

    @Override
    public UserIdentificationInfo handleRetrieveIdentity(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {

        String token = getTokenFromRequest(httpRequest);

        if (token == null) {
            log.debug("Found no token in the request.");
            return null;
        }

        String userName = getUserByToken(token);
        if (userName == null) {
            log.debug(String.format("No user bound to the token '%s' (maybe it has been revoked), returning null.", token));
            return null;
        }
        // Don't retrieve identity for anonymous user unless 'allowAnonymous' parameter is explicitly set to true in
        // the authentication plugin configuration
        UserManager userManager = Framework.getService(UserManager.class);
        if (userManager != null && userName.equals(userManager.getAnonymousUserId()) && !allowAnonymous) {
            log.debug("Anonymous user is not allowed to get authenticated by token, returning null.");
            return null;
        }


        return new UserIdentificationInfo(userName, userName);
    }

    /**
     * Gets the token from the request if present else null.
     */
    private String getTokenFromRequest(HttpServletRequest httpRequest) {
        String token = httpRequest.getParameter(TOKEN_PARAM);

        if (token == null) {
            token = getTokenFromHeader(httpRequest);
        }

        return token;
    }

    /**
     * Gets the token from the request header if present else null.
     */
    private String getTokenFromHeader(HttpServletRequest httpRequest) {
        String token = null;

        String headerValue = httpRequest.getHeader(TOKEN_HEADER);

        if (StringUtils.isNotBlank(headerValue) && StringUtils.startsWith(headerValue, TOKEN_PREFIX)) {
            token = StringUtils.trim(StringUtils.removeStart(headerValue, TOKEN_PREFIX));
        }

        return token;
    }

    @Override
    public Boolean needLoginPrompt(HttpServletRequest httpRequest) {
        return false;
    }

    @Override
    public void initPlugin(Map<String, String> parameters) {
        if (parameters.containsKey(ALLOW_ANONYMOUS_KEY)) {
            allowAnonymous = Boolean.valueOf(parameters.get(ALLOW_ANONYMOUS_KEY));
        }
        if (parameters.containsKey(ALGORITHM_ID_KEY)) {
            algorithmId = parameters.get(ALGORITHM_ID_KEY);
        }
    }

    @Override
    public List<String> getUnAuthenticatedURLPrefix() {
        return null;
    }

    protected String getUserByToken(String token) {

        Map<String, Object> payload = getJWTTokenService().getPayload(token, algorithmId);
        String userId = (String) payload.get("userId");

        return userId;
    }

    protected JWTTokenService getJWTTokenService() {
        if (jWTTokenService == null) {
            jWTTokenService = Framework.getService(JWTTokenService.class);
        }

        return jWTTokenService;
    }
}
