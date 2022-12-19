package org.acme.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RefreshAccessTokenRequest {
    @JsonProperty("refresh_token")
    public String refreshToken;
}
