package org.acme.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.hibernate.validator.constraints.URL;

import javax.validation.constraints.NotEmpty;

public class ExchangeTokenRequest {

    @NotEmpty(message = "Authorization code can not be empty")
    @JsonProperty("auth_code")
    public String authCode;

    @NotEmpty(message = "Redirect uri can not be empty")
    @JsonProperty("redirect_uri")
    @URL(message = "Please enter a valid URL")
    public String redirectUri;
}
