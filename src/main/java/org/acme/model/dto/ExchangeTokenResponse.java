package org.acme.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class ExchangeTokenResponse {
    @JsonProperty("access_token")
    public String accessToken;
    @JsonProperty("user_info")
    public CustomUserInfo userInfo;
}
