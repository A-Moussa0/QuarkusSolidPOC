package org.acme.api;

import io.quarkus.security.identity.SecurityIdentity;
import org.acme.model.Employee;
import org.acme.model.dto.CreateEmployee;
import org.acme.service.EmployeeService;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;
import org.jboss.resteasy.reactive.RestPath;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.util.List;

@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Path("/api/v1/employees")
public class EmployeesResource {

    Logger logger;
    EmployeeService employeeService;

    @Inject
    SecurityIdentity securityIdentity;

    public EmployeesResource(Logger logger, EmployeeService employeeService, SecurityIdentity securityIdentity) {
        this.logger = logger;
        this.employeeService = employeeService;
        this.securityIdentity = securityIdentity;
    }

    @GET
    @NoCache
    @RolesAllowed("user")
    public Response getAllEmployees() {
        List<Employee> employees = employeeService.findAllEmployees();
        logger.info("Total number of Employees " + employees);
        return Response.ok(employees).build();
    }

    @POST
    @Transactional
    @RolesAllowed("user")
    public Response createEmployee(@Valid CreateEmployee employeeToRegister, @Context UriInfo uriInfo) {
        Employee createdEmployee = employeeService.createEmployee(employeeToRegister);
        UriBuilder builder = uriInfo.getAbsolutePathBuilder().path(Long.toString(createdEmployee.id));
        logger.info("New employee created with id " + createdEmployee.id);
        return Response.created(builder.build()).build();
    }

    @PUT
    @Transactional
    @RolesAllowed("user")
    public Response updateEmployee(@Valid Employee employeeToUpdate) {
        Employee employee = employeeService.updateEmployee(employeeToUpdate);
        logger.info("Employee updated with new values " + employee);
        return Response.ok(employee).build();
    }

    @DELETE
    @Transactional
    @RolesAllowed("user")
    @Path("/{id}")
    public Response deleteEmployee(@RestPath Long id) {
        employeeService.deleteEmployee(id);
        logger.info("Employee deleted" + id);
        return Response.noContent().build();
    }

    @GET
    @Transactional
    @RolesAllowed("user")
    @Path("/{id}")
    public Response getEmployee(@RestPath Long id) {
        Employee employee = employeeService.getEmployee(id);
        logger.info("Employee found" + id);
        return Response.ok(employee).build();
    }
}
