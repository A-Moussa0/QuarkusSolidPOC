package org.acme.api;

import io.quarkus.security.identity.SecurityIdentity;
import org.acme.model.User;
import org.acme.model.dto.RegisterUser;
import org.acme.service.UserService;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;
import org.jboss.resteasy.reactive.RestPath;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.util.List;

@Path("/api/v1/users")
public class UsersResource {

    Logger logger;
    UserService userService;

    @Inject
    SecurityIdentity securityIdentity;

    public UsersResource(Logger logger, UserService userService, SecurityIdentity securityIdentity) {
        this.logger = logger;
        this.userService = userService;
        this.securityIdentity = securityIdentity;
    }


    @GET
    @NoCache
    //@RolesAllowed("admin")
    public Response getAllUsers() {
        List<User> users = userService.findAllUsers();
        logger.debug("Total number of Users " + users);
        return Response.ok(users).build();
    }

    @POST
    @Transactional
    public Response createUser(@Valid RegisterUser userToRegister, @Context UriInfo uriInfo) {
        User createdUser = userService.persistUser(userToRegister);
        UriBuilder builder = uriInfo.getAbsolutePathBuilder().path(Long.toString(createdUser.id));
        logger.debug("New user created with id " + createdUser.id);
        return Response.created(builder.build()).build();
    }

    @PUT
    @Transactional
    public Response updateUser(@Valid User userToUpdate) {
        User user = userService.updateUser(userToUpdate);
        logger.debug("User updated with new values " + user);
        return Response.ok(user).build();
    }

    @DELETE
    @Transactional
    @Path("/{id}")
    public Response deleteUser(@RestPath Long id) {
        userService.deleteUser(id);
        logger.debug("User deleted");
        return Response.noContent().build();
    }

}
