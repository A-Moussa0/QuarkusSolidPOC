package org.acme.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.AllArgsConstructor;
import lombok.ToString;

@ToString
@AllArgsConstructor
public class AuthTokenResponse {
    public JsonNode keycloakResponse;
    public ExchangeTokenResponse exchangeTokenResponse;
}
