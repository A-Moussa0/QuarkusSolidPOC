package org.acme.model.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;

public class CreateEmployee {
    @NotEmpty(message = "email can not be empty")
    @Email(message = "please enter a valid email")
    public String email;

    @NotEmpty(message = "username can not be empty")
    @Size(min = 3, max = 50, message = "username length has to be between 3 and 50 characters")
    public String username;

    @NotEmpty(message = "password can not be empty")
    public String password;

    @NotEmpty(message = "first_name can not be empty")
    public String first_name;

    @NotEmpty(message = "last_name can not be empty")
    public String last_name;

    @NotEmpty(message = "phone_number can not be empty")
    public String phone_number;

    @Size(min = 4, max = 10, message = "zipcode length has to be between 4 and 10 characters")
    @NotEmpty(message = "zip_code can not be empty")
    public String zip_code;

}
