package org.acme.service;

import io.quarkus.panache.common.Sort;
import org.acme.model.Role;
import org.acme.model.Status;
import org.acme.model.User;
import org.acme.model.dto.RegisterUser;

import javax.enterprise.context.ApplicationScoped;
import javax.transaction.Transactional;
import javax.validation.Valid;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotFoundException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static javax.transaction.Transactional.TxType.REQUIRED;
import static javax.transaction.Transactional.TxType.SUPPORTS;

@ApplicationScoped
@Transactional(REQUIRED)
public class UserService {
    private final String activeStatus = String.valueOf(Status.ACT);
    private final String deletedStatus = String.valueOf(Status.DEL);

    @Transactional(SUPPORTS)
    public List<User> findAllUsers() {
        return User.findAll(Sort.by("status")).list();
    }

    @Transactional(SUPPORTS)
    public User findUserById(Long id) {
        Optional<User> user = User.findByIdOptional(id);
        return user.orElseThrow(NotFoundException::new);
    }

    @Transactional(SUPPORTS)
    public User findActiveUserByUsername(String username) {
        User user = User.find("username",username).firstResult();
        existingActiveUserChecks(user);
        return user;
    }

    private void existingActiveUserChecks(User user) {
        if (user == null)
            throw new NotFoundException("user not found");
        if (!user.isPersistent())
            throw new NotFoundException("user not found");
        if (!Objects.equals(user.status, activeStatus))
            throw new NotFoundException("user not found");
    }

    @Transactional(SUPPORTS)
    private boolean usernameTaken(String username) {
        long existingUser = User.count("username", username);
        return existingUser > 0;
    }

    @Transactional(SUPPORTS)
    public User persistUser(@Valid RegisterUser registerUser) {
        if (usernameTaken(registerUser.username));
            //TODO: throw something - 409
        User user = new User();
        user.username = registerUser.username;
        user.first_name = registerUser.first_name;
        user.last_name = registerUser.last_name;
        user.email = registerUser.email;
        user.phone_number = registerUser.phone_number;
        user.zip_code = registerUser.zip_code;
        user.status = activeStatus;
        user.role = String.valueOf(Role.user);
        user.persist();
        return user;
    }

    @Transactional(SUPPORTS)
    public User updateUser(@Valid User userToUpdate) {
        if (userToUpdate.username == null || userToUpdate.username.isEmpty())
            throw new BadRequestException("Must specify username");
        User userEntity = findActiveUserByUsername(userToUpdate.username);
        if (userToUpdate.email != null) userEntity.email = userToUpdate.email;
        if (userToUpdate.first_name != null) userEntity.first_name = userToUpdate.first_name;
        if (userToUpdate.last_name != null) userEntity.last_name = userToUpdate.last_name;
        if (userToUpdate.phone_number != null) userEntity.phone_number = userToUpdate.phone_number;
        if (userToUpdate.zip_code != null) userEntity.zip_code = userToUpdate.zip_code;
        return userEntity;
    }

    @Transactional(SUPPORTS)
    public void deleteUser(Long id) {
        User user = findUserById(id);
        existingActiveUserChecks(user);
        user.status = deletedStatus;
    }
}
