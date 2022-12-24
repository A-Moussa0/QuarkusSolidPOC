package org.acme.model.dto;

import javax.validation.constraints.NotNull;

public class UpdateEmployeeRequest {
    @NotNull(message = "id can not be empty")
    public Long id;
    public String first_name;
    public String last_name;
    public String username;
    public String email;
    public String phone_number;
    public String zip_code;
    public String status;
    public String role;
}
