package util;

import java.util.Calendar;

public class ChangePassword {

    public String oldPwd;
    public String newPwd;
    public String confirmation;

    public ChangePassword() {

    }

    public ChangePassword(String oldPwd, String newPwd, String confirmation) {
        this.oldPwd = oldPwd;
        this.newPwd = newPwd;
        this.confirmation = confirmation;
    }

    private boolean nonEmptyOrBlankField(String field) {
        return field != null && !field.isBlank();
    }

    public boolean validChangePassword() {
        return nonEmptyOrBlankField(oldPwd) &&
                nonEmptyOrBlankField(newPwd) &&
                nonEmptyOrBlankField(confirmation) &&
                newPwd.equals(confirmation);
    }
}
