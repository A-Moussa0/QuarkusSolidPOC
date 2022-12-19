package org.acme.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class RefreshAccessTokenResponse {
    @JsonProperty("access_token")
    public String accessToken;
}
