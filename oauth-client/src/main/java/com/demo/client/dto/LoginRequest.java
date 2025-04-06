package com.demo.client.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.io.Serializable;

@Builder
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest implements Serializable {

    @NotBlank(message = "please enter your account")
    private String account;
    @NotBlank(message = "please enter your password")
    private String pw;

    private String email;
}
