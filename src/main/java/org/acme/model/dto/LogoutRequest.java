package org.acme.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

public class LogoutRequest {
    @NotEmpty(message = "email can not be empty")
    @Email(message = "please enter a valid email")
    public String email;
}
