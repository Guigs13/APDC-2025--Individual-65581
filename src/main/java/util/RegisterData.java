package util;

import Enums.CountState;
import Enums.UsersRole;

import java.util.regex.Pattern;

public class RegisterData {

    public String username;
    public String password;
    public String confirmation;
    public String email;
    public String phone;
    public String fullName;
    public String status;

    //Can be empty
    public String cc;
    public String NIF;
    public String employer;
    public String function;
    public String address;
    public String employerNIF;

    //Already with a value
    public String role;
    public String state;


    public RegisterData() {

    }

    public RegisterData(String username, String password, String confirmation, String email, String fullName,String phone, String status) {
        this.username = username;
        this.password = password;
        this.confirmation = confirmation;
        this.email = email;
        this.fullName = fullName;
        this.phone = phone;
        this.status = status;
        this.role = UsersRole.ENDUSER.toString();
        this.state = CountState.DESATIVADA.toString();
    }

    private boolean nonEmptyOrBlankField(String field) {
        return field != null && !field.isBlank();
    }

    public boolean validRegistration() {
        String emailRegex = "^[\\w.-]+@[\\w.-]+\\.[a-zA-Z]{2,}$";

        String passwordRegex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^\\w\\s]).{8,}$";

        return nonEmptyOrBlankField(username) &&
                nonEmptyOrBlankField(password) &&
                nonEmptyOrBlankField(email) &&
                nonEmptyOrBlankField(fullName) &&
                nonEmptyOrBlankField(status) &&
                (status.equals("público") || status.equals("privado")) &&
                password.equals(confirmation) &&
                Pattern.matches(emailRegex, email) &&
                Pattern.matches(passwordRegex, password);
    }

}