package org.acme.api;

import io.quarkus.oidc.IdToken;
import org.acme.model.dto.*;
import org.acme.service.AuthService;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


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
        ExchangeTokenResponse exchangeTokenResponse = authService.exchangeToken(exchangeTokenRequest);
        logger.info("code exchanged " + exchangeTokenResponse.accessToken);
        return Response.ok(exchangeTokenResponse).build();
    }

    @POST
    @Path("/refresh-access")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response refreshAccessToken(@Valid RefreshAccessTokenRequest refreshAccessTokenRequest) throws BadRequestException {
        AuthTokenResponse authTokenResponse = authService.newAccessToken(refreshAccessTokenRequest.refreshToken);
        RefreshAccessTokenResponse refreshAccessTokenResponse = new RefreshAccessTokenResponse(authTokenResponse.accessToken);
        logger.info("access token refreshed " + refreshAccessTokenResponse);
        return Response.ok(refreshAccessTokenResponse).build();
    }

    @POST
    @Path("/logout")
    @RolesAllowed({"user", "admin"})
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response logout() {
        authService.logout(idToken.getTokenID());
        logger.info("Employee logged out with idToke " + idToken);
        return Response.ok().build();
    }
}
