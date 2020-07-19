package org.ravi.java.messenger.oauth;

/**
 * @author rbhavsar
 * Created on 7/19/20.
 */
public class AuthParams {
  private String authorizationHeader = null;
  private String oauth_consumer_key = null;
  private String oauth_signature_method = null;
  private String oauth_signature = null;
  private String oauth_timestamp_str = null;
  private String oauth_nonce = null;
  private String oauth_version = null;
  private String auth_scheme = null;
  private String basic_auth_key = null;
  private boolean isBasicAuthentication = false;
  public String getAuthorizationHeader() {
    return authorizationHeader;
  }
  public void setAuthorizationHeader(String authorizationHeader) {
    this.authorizationHeader = authorizationHeader;
  }
  public String getOauth_consumer_key() {
    return oauth_consumer_key;
  }
  public void setOauth_consumer_key(String oauth_consumer_key) {
    this.oauth_consumer_key = oauth_consumer_key;
  }
  public String getOauth_signature_method() {
    return oauth_signature_method;
  }
  public void setOauth_signature_method(String oauth_signature_method) {
    this.oauth_signature_method = oauth_signature_method;
  }
  public String getOauth_signature() {
    return oauth_signature;
  }
  public void setOauth_signature(String oauth_signature) {
    this.oauth_signature = oauth_signature;
  }
  public String getOauth_timestamp_str() {
    return oauth_timestamp_str;
  }
  public void setOauth_timestamp_str(String oauth_timestamp_str) {
    this.oauth_timestamp_str = oauth_timestamp_str;
  }
  public String getOauth_nonce() {
    return oauth_nonce;
  }
  public void setOauth_nonce(String oauth_nonce) {
    this.oauth_nonce = oauth_nonce;
  }
  public String getOauth_version() {
    return oauth_version;
  }
  public void setOauth_version(String oauth_version) {
    this.oauth_version = oauth_version;
  }
  public String getAuth_scheme() {
    return auth_scheme;
  }
  public void setAuth_scheme(String auth_scheme) {
    this.auth_scheme = auth_scheme;
  }
  public String getBasic_auth_key() {
    return basic_auth_key;
  }
  public void setBasic_auth_key(String basic_auth_key) {
    this.basic_auth_key = basic_auth_key;
  }
  public boolean isBasicAuthentication() {
    return isBasicAuthentication;
  }
  public void setBasicAuthentication(boolean isBasicAuthentication) {
    this.isBasicAuthentication = isBasicAuthentication;
  }
}
