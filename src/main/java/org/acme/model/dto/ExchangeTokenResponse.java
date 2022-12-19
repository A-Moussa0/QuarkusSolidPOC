package org.acme.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import org.keycloak.representations.UserInfo;

import java.util.ArrayList;

@AllArgsConstructor
public class ExchangeTokenResponse {
    @JsonProperty("access_token")
    public String accessToken;
    @JsonProperty("refresh_token")
    public String refreshToken;
    @JsonProperty("user_info")
    public CustomUserInfo userInfo;
}
