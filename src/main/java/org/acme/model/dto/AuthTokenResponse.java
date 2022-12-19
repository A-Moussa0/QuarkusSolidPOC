package org.acme.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.ToString;

@ToString
public class AuthTokenResponse {
    @JsonProperty("access_token")
    public String accessToken;
    @JsonProperty("expires_in")
    public int expiresIn;
    @JsonProperty("refresh_expires_in")
    public int refreshExpiresIn;
    @JsonProperty("refresh_token")
    public String refreshToken;
    @JsonProperty("token_type")
    public String tokenType;
    @JsonProperty("id_token")
    public String idToken;
    @JsonProperty("not-before-policy")
    public int not_before_policy;
    public String scope;
}
