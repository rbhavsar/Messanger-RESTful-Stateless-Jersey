package org.ravi.java.messenger.oauth;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.LogManager;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.apache.log4j.Logger;
import org.glassfish.jersey.internal.util.Base64;
import org.ravi.java.messenger.exception.UnauthorizedAccessException;


/**
 * @author rbhavsar
 * Created on 7/19/20.
 */
@Provider
@Authorized
public class OAuthAuthenticationFilter implements ContainerRequestFilter {

  private static final Logger logger = LogManager.getLogger(OAuthAuthenticationFilter.class);
  private static boolean enableAuthentication = true;
  public static String baseURL = null;

  @Inject
  private Util util;
  @Inject
  @Singleton
  private OAuth1SignatureBuilder oAuth1SignatureBuilder;


  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    if (!enableAuthentication) {
      logger.debug("OAuth Authentication is disabled");
      return;
    }
    try {
      AuthParams authParams = extractOAuthHeaders(requestContext);
      logger.info("isBasicAuthentication: "+authParams.isBasicAuthentication());
      if(authParams.isBasicAuthentication())
      {
        varifyBasicAuthentication(authParams);
      }
      else {
        verifyOAuthSignature(requestContext, authParams);
      }

    } catch (UnauthorizedAccessException uae) {
      logger.error(uae.getMessage(), uae);
      ErrorMessage errorMessage = ErrorMessages.apiUnauthorized(uae.getMessage());
      throw new WebApplicationException(
          Response.status(Response.Status.UNAUTHORIZED).
              entity(errorMessage).
              build());
    }
  }

  private void varifyBasicAuthentication(AuthParams authParams) throws UnauthorizedAccessException {
    if(authParams.getBasic_auth_key()==null)
    {throw new UnauthorizedAccessException("Missing required Authentication String");}

    String username = util.getConfigParameter("auth.UserName",true);
    String password = util.getConfigParameter("auth.Password",true);
    String key = Base64.encodeAsString(username+":"+password);
    if(key.equals(authParams.getBasic_auth_key()))
    {
      return;
    }
    else
    {

      throw new UnauthorizedAccessException("Invalid Authentication String");
    }
  }

  private AuthParams extractOAuthHeaders(ContainerRequestContext requestContext) throws UnauthorizedAccessException {
    AuthParams authParams = new AuthParams();
    authParams.setAuthorizationHeader(requestContext.getHeaderString("Authorization"));
    printOAuthHeader(authParams.getAuthorizationHeader());
    if (authParams.getAuthorizationHeader() == null || authParams.getAuthorizationHeader().isEmpty())
      throw new UnauthorizedAccessException("Missing required OAuth headers");
    Map<String, String> map = AuthorizationHeaderParser.parse(authParams.getAuthorizationHeader());
    authParams.setAuth_scheme(map.get(":auth-scheme"));
    // if basic authorization
    if(authParams.getAuth_scheme().equals("Basic"))
    {   authParams.setBasicAuthentication(true);
      authParams.setBasic_auth_key(map.get("basic_auth_key"));
      return authParams;
    }

    authParams.setOauth_consumer_key(map.get("oauth_consumer_key"));
    authParams.setOauth_signature_method(map.get("oauth_signature_method"));
    authParams.setOauth_signature(map.get("oauth_signature"));
    authParams.setOauth_timestamp_str(map.get("oauth_timestamp"));
    authParams.setOauth_nonce(map.get("oauth_nonce"));
    authParams.setOauth_version(map.get("oauth_version"));
    validateOAuthHeaders(authParams);
    return authParams;
  }

  private void printOAuthHeader(String authorizationHeader) {
    logger.trace("===========Authorization header=======:" + authorizationHeader);
  }

  private void validateOAuthHeaders(AuthParams authParams) throws UnauthorizedAccessException {
    if (authParams.getOauth_consumer_key() == null || authParams.getOauth_signature() == null || authParams.getOauth_timestamp_str() == null || authParams.getOauth_nonce() == null || authParams.getOauth_signature_method() == null)
      throw new UnauthorizedAccessException("Missing required OAuth headers");
    if (authParams.getOauth_signature_method() == null || !authParams.getOauth_signature_method().equals("HMAC-SHA256"))
      throw new UnauthorizedAccessException("Invalid oauth signature method :" + authParams.getOauth_signature_method());
    if (authParams.getOauth_version() == null || !authParams.getOauth_version().equals("1.0"))
      throw new UnauthorizedAccessException("Invalid oauth_version :" + authParams.getOauth_version());
    try {
      Long.parseLong(authParams.getOauth_timestamp_str());
    } catch (NumberFormatException nfe) {
      throw new UnauthorizedAccessException("Invalid oauth_timestamp : " + authParams.getOauth_timestamp_str());
    }
  }

  private void verifyOAuthSignature(ContainerRequestContext requestContext, AuthParams authParams) throws UnauthorizedAccessException {
    String CONSUMER_KEY = util.getConfigParameter(OAUTH_CONSUMER_KEY);
    String SECRET_KEY = util.getConfigParameter(OAUTH_SECRET_KEY);

    if (!CONSUMER_KEY.equals(authParams.getOauth_consumer_key()))
      throw new UnauthorizedAccessException("Unauthorized Request");

    try {
      String httpMethod = requestContext.getMethod();
      String url = baseURL + "/" + requestContext.getUriInfo().getPath();
      Map<String, Object> additionalParams = null;
      if (requestContext.getUriInfo().getPathParameters() != null) {
        additionalParams = new HashMap<>();
        for (String key : requestContext.getUriInfo().getPathParameters().keySet()) {
          additionalParams.put(key, requestContext.getUriInfo().getPathParameters().get(key));
        }
      }

      byte[] requestBody = null;
      // Set the request body if making a POST or PUT request
	    /*if ("POST".equals(httpMethod)  || "PUT".equals(httpMethod))
	    {
	    		String json = IOUtils.toString(requestContext.getEntityStream(), "UTF-8");
	    		requestBody =   json.getBytes("UTF-8");
	    }*/
      Map<String, String> oauthParams = new LinkedHashMap<String, String>();
      oauthParams.put("oauth_consumer_key", authParams.getOauth_consumer_key());
      oauthParams.put("oauth_signature_method", authParams.getOauth_signature_method());
      oauthParams.put("oauth_timestamp", authParams.getOauth_timestamp_str());
      oauthParams.put("oauth_nonce", authParams.getOauth_nonce());
      oauthParams.put("oauth_version", "1.0");
      String signature = oAuth1SignatureBuilder.buildSignature(httpMethod, new URL(url), oauthParams, requestBody, SECRET_KEY + "&");

      if (!signature.equals(authParams.getOauth_signature()))
        throw new UnauthorizedAccessException("Unauthorized Request");
    } catch (Exception e) {
      logger.error(e, e);
      throw new UnauthorizedAccessException("Unauthorized Request");
    }
  }

  //Test Only
  public void setUtil(Util util) {
    this.util = util;
  }
}
