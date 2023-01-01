package org.acme.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.quarkus.oidc.IdToken;
import org.acme.Utils;
import org.acme.model.dto.*;
import org.acme.service.AuthService;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.util.List;


@Path("/api/v1/auth")
public class AuthResource {
    @Inject
    Logger logger;
    @Inject
    @IdToken
    JsonWebToken idToken;
    AuthService authService;
    @Inject
    public AuthResource(AuthService authService) {
        this.authService = authService;
    }

    @POST
    @Path("/exchange-token")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response exchangeToken(@Valid ExchangeTokenRequest exchangeTokenRequest) throws BadRequestException {
        AuthTokenResponse authTokenResponse = authService.exchangeToken(exchangeTokenRequest);
        logger.info("code exchanged");
        List<NewCookie> newCookies = Utils.getAuthCookies(authTokenResponse.keycloakResponse);
        return Response.ok(authTokenResponse.exchangeTokenResponse).cookie(newCookies.toArray(new NewCookie[]{})).build();
    }

    @POST
    @Path("/refresh-access")
    @RolesAllowed({"user","admin"})
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response refreshAccessToken(@CookieParam("jwt_refresh") String refreshToken) throws BadRequestException {
        JsonNode keycloakResponse = authService.newAccessToken(refreshToken);
        RefreshAccessTokenResponse refreshAccessTokenResponse = new RefreshAccessTokenResponse(keycloakResponse.get("access_token").asText());
        logger.info("access token refreshed " + refreshAccessTokenResponse);
        List<NewCookie> newCookies = Utils.getAuthCookies(keycloakResponse);
        return Response.ok(refreshAccessTokenResponse).cookie(newCookies.toArray(new NewCookie[]{})).build();
    }

    @POST
    @Path("/logout")
    @RolesAllowed({"user","admin"})
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response logout() {
        authService.logout(idToken.getTokenID());
        logger.info("Employee logged out with idToke " + idToken);
        return Response.ok().build();
    }
}
