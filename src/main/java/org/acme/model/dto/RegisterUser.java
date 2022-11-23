package org.acme.model.dto;

import org.hibernate.validator.constraints.UniqueElements;

import javax.persistence.UniqueConstraint;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class RegisterUser {
    @NotNull(message = "email can not be empty")
    @Email(message = "please enter a valid email")
    public String email;

    @NotNull(message = "username can not be empty")
    @Size(min = 3, max = 50, message = "username length has to be between 3 and 50 characters")
    public String username;

    public String first_name;

    public String last_name;

    public String phone_number;

    @Size(min = 4, max = 10, message = "zipcode length has to be between 4 and 10 characters")
    public String zip_code;

}
