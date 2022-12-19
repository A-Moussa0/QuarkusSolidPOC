package org.acme.service;

import io.quarkus.panache.common.Sort;
import org.acme.model.Employee;
import org.acme.model.Role;
import org.acme.model.Status;
import org.acme.model.dto.CreateEmployee;
import org.jboss.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.validation.Valid;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static javax.transaction.Transactional.TxType.REQUIRED;
import static javax.transaction.Transactional.TxType.SUPPORTS;

@ApplicationScoped
@Transactional(REQUIRED)
public class EmployeeService {
    private final String activeStatus = String.valueOf(Status.ACT);
    private final String deletedStatus = String.valueOf(Status.DEL);
    @Inject
    Logger logger;

    @Transactional(SUPPORTS)
    public List<Employee> findAllEmployees() {
        List<Employee> employees;
        try {
            logger.info("Fetching all employees");
            employees = Employee.findAll(Sort.by("status")).list();
        } catch (Exception e) {
            logger.fatal("something bad happened when fetching employees");
            throw new WebApplicationException("Something bad happened, oops", Response.Status.INTERNAL_SERVER_ERROR);
        }
        return employees;
    }

    private void existingActiveEmployeeChecks(Employee employee) {
        if (employee == null)
            throw new NotFoundException("employee not found");
        if (!employee.isPersistent())
            throw new NotFoundException("employee not found");
        if (!Objects.equals(employee.status, activeStatus))
            throw new NotFoundException("employee not found");
    }

    @Transactional(SUPPORTS)
    public Employee createEmployee(@Valid CreateEmployee createEmployee) {
        if (userAlreadyExists("username", createEmployee.username) || userAlreadyExists("email", createEmployee.email)) {
            logger.info("User exists" + createEmployee.username);
            throw new WebApplicationException("User exists", Response.Status.CONFLICT);
        }
        Employee employee = new Employee();
        try {
            employee.username = createEmployee.username;
            employee.first_name = createEmployee.first_name;
            employee.last_name = createEmployee.last_name;
            employee.email = createEmployee.email;
            employee.phone_number = createEmployee.phone_number;
            employee.zip_code = createEmployee.zip_code;
            employee.status = activeStatus;
            employee.role = String.valueOf(Role.user);
            employee.persist();
        } catch (Exception e) {
            logger.fatal("Creating employee failed" + createEmployee.username + "exception: " + e.getMessage());
            throw new WebApplicationException("Something bad happened, oops", Response.Status.INTERNAL_SERVER_ERROR);
        }
        return employee;
    }

    private boolean userAlreadyExists(String key, String value) {
        long existingEmployee = Employee.count(key, value);
        return existingEmployee > 0;
    }

    @Transactional(SUPPORTS)
    public Employee updateEmployee(@Valid Employee employeeToUpdate) {
        if (employeeToUpdate.username == null || employeeToUpdate.username.isEmpty())
            throw new BadRequestException("Must specify username");
        Employee employeeEntity;
        try {
            employeeEntity = findActiveEmployeeBy("username",employeeToUpdate.username);
            if (employeeToUpdate.email != null) employeeEntity.email = employeeToUpdate.email;
            if (employeeToUpdate.first_name != null) employeeEntity.first_name = employeeToUpdate.first_name;
            if (employeeToUpdate.last_name != null) employeeEntity.last_name = employeeToUpdate.last_name;
            if (employeeToUpdate.phone_number != null) employeeEntity.phone_number = employeeToUpdate.phone_number;
            if (employeeToUpdate.zip_code != null) employeeEntity.zip_code = employeeToUpdate.zip_code;
        } catch (Exception e) {
            logger.fatal("couldn't update Employee" + employeeToUpdate.username + "exception: " + e.getMessage());
            throw new WebApplicationException("Something bad happened, oops", Response.Status.INTERNAL_SERVER_ERROR);
        }
        return employeeEntity;
    }

    @Transactional(SUPPORTS)
    public void deleteEmployee(Long id) {
        Employee employee;
        try {
            employee = findEmployeeById(id);
            existingActiveEmployeeChecks(employee);
        } catch (Exception e) {
            logger.fatal("couldn't delete Employee" + id + "exception: " + e.getMessage());
            throw new WebApplicationException("Something bad happened, oops", Response.Status.INTERNAL_SERVER_ERROR);
        }
        employee.status = deletedStatus;
    }

    @Transactional(SUPPORTS)
    public Employee getEmployee(Long id) {
        Employee employee;
        try {
        employee = findEmployeeById(id);
        existingActiveEmployeeChecks(employee);
        } catch (Exception e) {
            logger.fatal("couldn't retrieve Employee" + id + "exception: " + e.getMessage());
            throw new WebApplicationException("Something bad happened, oops", Response.Status.INTERNAL_SERVER_ERROR);
        }
        return employee;
    }

    @Transactional(SUPPORTS)
    public Employee findEmployeeById(Long id) {
        Optional<Employee> employee = Employee.findByIdOptional(id);
        return employee.orElseThrow(NotFoundException::new);
    }

    @Transactional(SUPPORTS)
    public Employee findActiveEmployeeBy(String key, String value) {
        Employee employee = Employee.find(key, value).firstResult();
        existingActiveEmployeeChecks(employee);
        return employee;
    }
}
