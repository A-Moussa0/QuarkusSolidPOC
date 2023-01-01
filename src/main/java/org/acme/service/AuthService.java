package org.acme.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.acme.model.dto.AuthTokenResponse;
import org.acme.model.dto.CustomUserInfo;
import org.acme.model.dto.ExchangeTokenRequest;
import org.acme.model.dto.ExchangeTokenResponse;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;


@ApplicationScoped
public class AuthService {
    @Inject
    Logger logger;
    @RestClient
    IAuthService authService;

    private final String clientId;
    private final String secret;
    private final String scope;

    @Inject
    public AuthService(@ConfigProperty(name = "quarkus.oidc.client-id") String clientId,
                       @ConfigProperty(name = "quarkus.oidc.credentials.secret") String secret,
                       @ConfigProperty(name = "qsp.auth.keycloak.scope")  String scope) {
        this.clientId = clientId;
        this.secret = secret;
        this.scope = scope;
    }

    public AuthTokenResponse exchangeToken(ExchangeTokenRequest exchangeTokenRequest) {
        JsonNode keycloakResponse;
        try {
            Form authTokenForm = new Form()
                    .param("client_id", clientId)
                    .param("client_secret", secret)
                    .param("grant_type", "authorization_code")
                    .param("scope", scope)
                    .param("redirect_uri", exchangeTokenRequest.redirectUri)
                    .param("code", exchangeTokenRequest.authCode);
            keycloakResponse = authService.callTokenApi(authTokenForm);
        }
        catch (Exception e) {
            logger.fatal("Error with request for token: " + exchangeTokenRequest.authCode + e.getMessage());
            if (e.getMessage().contains("status code: 400"))
                throw new BadRequestException("Bad refresh token request");
            throw new WebApplicationException("Something bad happened, oops", Response.Status.INTERNAL_SERVER_ERROR);
        }
        return new AuthTokenResponse(keycloakResponse,
                buildExchangeResponse(keycloakResponse.get("access_token").asText())
        );
    }

    private ExchangeTokenResponse buildExchangeResponse(String accessToken) {
        CustomUserInfo userInfo = getUserInfo(accessToken);
        return new ExchangeTokenResponse(accessToken, userInfo);
    }

    private CustomUserInfo getUserInfo(String accessToken) {
        return authService.callUserInfoApi("Bearer " + accessToken);
    }

    public JsonNode newAccessToken(String refreshToken) {
        JsonNode keycloakResponse;
        AuthTokenResponse authTokenResponse;
        try {
            Form refreshTokenForm = new Form()
                    .param("client_id", clientId)
                    .param("client_secret", secret)
                    .param("grant_type", "refresh_token")
                    .param("refresh_token", refreshToken);
            keycloakResponse = authService.callTokenApi(refreshTokenForm);
        }
        catch (Exception e){
            logger.fatal("Error with newAccessToken: " + e.getMessage());
            if (e.getMessage().contains("status code: 400"))
                throw new BadRequestException("Bad refresh token request");
            throw new WebApplicationException("Something bad happened, oops", Response.Status.INTERNAL_SERVER_ERROR);
        }
        return keycloakResponse;
    }
    public void logout(String idToken) {
        try {
            Form logoutForm = new Form()
                    .param("client_id", clientId)
                    .param("id_token_hint", idToken);
            authService.callLogout(logoutForm);
        }
        catch (Exception e) {
            logger.fatal("Error with request for logout: " + e.getMessage());
            throw new WebApplicationException("Something bad happened, oops", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

//    public String register(CreateEmployee createUser) {
//        try {
//            UserRepresentation user = new UserRepresentation();
//            user.setUsername(createUser.username);
//            user.setFirstName(createUser.first_name);
//            user.setLastName(createUser.last_name);
//            user.setEmail(createUser.email);
//            user.setEnabled(true);
//            CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
//            credentialRepresentation.setType("password");
//            credentialRepresentation.setValue(createUser.password);
//            credentialRepresentation.setTemporary(false);
//            user.setCredentials(Collections.singletonList(credentialRepresentation));
//
//            Response loginResponse = instance.realm(realm).users().create(user);
//
//            logger.info("Response |  Status: " +loginResponse.getStatus() + "| Status Info: " + loginResponse.getStatusInfo());
//            String userId = loginResponse.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
//            return userId;
//        }
//        catch (Exception e){
//            logger.debug("Error with registration: " + e.getMessage());
//            throw e;
//        }
//    }



}
