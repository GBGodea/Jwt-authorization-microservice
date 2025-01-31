package com.godea.authorization.models.dto;

import com.godea.authorization.models.Role;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class UserDto {
    private String email;
    private Role role;

    @Override
    public String toString() {
        return "UserDTO\n" +
                "email: " + email + "\n" +
                "role: " + role;
    }
}
