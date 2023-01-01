package org.acme.service;

import com.fasterxml.jackson.databind.JsonNode;
import io.quarkus.rest.client.reactive.ClientExceptionMapper;
import org.acme.model.dto.CustomUserInfo;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.*;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@ApplicationScoped
@RegisterRestClient(configKey = "keycloak-auth-api")
@Path("realms/quarkus/protocol/openid-connect")
public interface IAuthService {
    @POST
    @Path("/token")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    JsonNode callTokenApi(Form authTokenExchangeRequest);

    @POST
    @Path("/logout")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    void callLogout(Form email);

    @GET
    @Path("/userinfo")
    @Produces(MediaType.APPLICATION_JSON)
    CustomUserInfo callUserInfoApi(@HeaderParam("Authorization") String accessToken);

    @ClientExceptionMapper
    static RuntimeException toException(Response response) {
        if (response.getStatus() == 500) {
            return new RuntimeException("The remote service responded with HTTP 500");
        }
        if (response.getStatus() == 400) {
            return new WebApplicationException("Request is invalid, status code: " + response.getStatus(), response);
        }
        return null;
    }
}
