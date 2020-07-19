package org.ravi.java.messenger.oauth;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Singleton;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;


/**
 * Very basic sample code that demonstrates how to make an OAuth 1.0 System-to-System
 * request to the LearningStudio API
 *
 *@author rbhavsar
 *
 */

@Singleton
public class OAuth1SignatureBuilder {

  private static final Logger logger = LogManager.getLogger(OAuth1SignatureBuilder.class);

  public static void main(final String[] args) throws Exception
  {
    // Setup the variables necessary to create the OAuth 1.0 signature and make the request
    String httpMethod  = "GET";
    String URI         = "http://localhost:8080/messages";
    String consumerKey = "consumer_key";
    String body        = "";
    String signatureMethod = "HMAC-SHA256";
    byte[] requestBody = null;
    //URL url = new URL(String.format("https://api.learningstudio.com/%s", URI));
    URL url = new URL(URI);

    // Set the Nonce and Timestamp parameters
    String nonce = "6839181";
    String timestamp = "1519583797";

    // Set the request body if making a POST or PUT request
    if ("POST".equals(httpMethod)  || "PUT".equals(httpMethod))
    {
      requestBody = body.getBytes("UTF-8");
    }


    // Create the OAuth parameter name/value pair
    Map<String, String> oauthParams = new LinkedHashMap<String, String>();
    oauthParams.put("oauth_consumer_key", consumerKey);
    oauthParams.put("oauth_signature_method", signatureMethod);
    oauthParams.put("oauth_timestamp", timestamp);
    oauthParams.put("oauth_nonce", nonce);
    oauthParams.put("oauth_version", "1.0");

    // Get the OAuth 1.0 Signature
    String signature = new OAuth1SignatureBuilder().buildSignature(httpMethod, url, oauthParams, requestBody, "consumer_secret&");
    System.out.println(String.format("OAuth 1.0 Signature = %s", signature));

    // Add the oauth_signature parameter to the set of OAuth Parameters
    oauthParams.put("oauth_signature", signature);

    // Generate a string of comma delimited: keyName="URL-encoded(value)" pairs
    StringBuilder sb = new StringBuilder();
    String delimiter = "";
    for (String keyName : oauthParams.keySet()) {
      sb.append(delimiter);
      String value = oauthParams.get((String) keyName);
      sb.append(keyName).append("=\"").append(URLEncoder.encode(value, "UTF-8")).append("\"");
      delimiter=",";
    }

    String urlString = url.toString();
    // omit the queryString from the url
    int startOfQueryString = urlString.indexOf('?');
    if(startOfQueryString != -1) {
      urlString = urlString.substring(0,startOfQueryString);
    }

    // Build the X-Authorization request header
    String xauth = String.format("OAuth realm=\"%s\",%s", urlString, sb.toString());
    System.out.println(String.format("X-Authorization request header = %s", xauth));


  }

  /**
   * Generates an OAuth 1.0 signature
   *
   * @param   httpMethod  The HTTP method of the request
   * @param   URL     The request URL
   * @param   oauthParams The associative set of signable oAuth parameters
   * @param   requestBody The serialized POST/PUT message body
   * @param   secret    Alphanumeric string used to validate the identity of the education partner (Private Key)
   *
   * @return  A string containing the Base64-encoded signature digest
   * @throws Exception
   */
  public String buildSignature(
      String httpMethod,
      URL url,
      Map<String, String> oauthParams,
      byte[] requestBody,
      String secret
  ) throws Exception
  {
    // Ensure the HTTP Method is upper-cased
    httpMethod = httpMethod.toUpperCase();

    // Construct the URL-encoded OAuth parameter portion of the signature base string
    String encodedParams = normalizeParams(httpMethod, url, oauthParams, requestBody);

    // URL-encode the relative URL
    String encodedUri = URLEncoder.encode(url.toString(), "UTF-8");

    // Build the signature base string to be signed with the Consumer Secret
    String baseString = String.format("%s&%s&%s", httpMethod, encodedUri, encodedParams);

    logger.trace("baseString=" + baseString);
    return encode(secret, baseString);
  }

  /**
   * Normalizes all OAuth signable parameters and url query parameters according to OAuth 1.0
   *
   * @param   httpMethod  The upper-cased HTTP method
   * @param   URL     The request URL
   * @param   oauthParams The associative set of signable oAuth parameters
   * @param   requstBody  The serialized POST/PUT message body
   *
   * @return  A string containing normalized and encoded oAuth parameters
   *
   * @throws  UnsupportedEncodingException
   */
  private static String normalizeParams(
      String httpMethod,
      URL url,
      Map<String, String> oauthParams,
      byte[] requestBody
  ) throws UnsupportedEncodingException
  {

    // Sort the parameters in lexicographical order, 1st by Key then by Value
    Map<String, String> kvpParams = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
    kvpParams.putAll(oauthParams);

    // Place any query string parameters into a key value pair using equals ("=") to mark
    // the key/value relationship and join each parameter with an ampersand ("&")
    if (url.getQuery() != null)
    {
      for(String keyValue : url.getQuery().split("&"))
      {
        String[] p = keyValue.split("=");
        kvpParams.put(p[0],p[1]);
      }

    }

    // Include the body parameter if dealing with a POST or PUT request
    if (("POST".equals(httpMethod) || "PUT".equals(httpMethod)) && requestBody != null)
    {
      String body = Base64.encodeBase64String(requestBody).replaceAll("\r\n", "");
      // url encode the body 2 times now before combining other params
      body = URLEncoder.encode(body, "UTF-8");
      body = URLEncoder.encode(body, "UTF-8");
      kvpParams.put("body", body);
    }

    // separate the key and values with a "="
    // separate the kvp with a "&"
    StringBuilder combinedParams = new StringBuilder();
    String delimiter="";
    for(String key : kvpParams.keySet()) {
      combinedParams.append(delimiter);
      combinedParams.append(key);
      combinedParams.append("=");
      combinedParams.append(kvpParams.get(key));
      delimiter="&";
    }

    // url encode the entire string again before returning
    return URLEncoder.encode(combinedParams.toString(), "UTF-8");
  }

  public static String encode(String key, String data) throws Exception {
    Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
    SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
    sha256_HMAC.init(secret_key);

    return URLEncoder.encode(Base64.encodeBase64String(sha256_HMAC.doFinal(data.getBytes("UTF-8"))).replaceAll("\r\n", ""), "UTF-8");
  }
}
