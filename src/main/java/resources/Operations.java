package resources;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import Enums.CountState;
import Enums.UsersRole;
import com.google.cloud.datastore.*;
import jakarta.ws.rs.*;

import com.google.cloud.datastore.StructuredQuery.CompositeFilter;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.gson.Gson;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.apache.commons.codec.digest.DigestUtils;
import util.AuthToken;
import util.ChangePassword;
import util.RegisterData;
import util.WorkSheet;


@Path("/operations")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class Operations {

    private static final Logger LOG = Logger.getLogger(Operations.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

    private final Gson g = new Gson();

    public Operations() {

    }

    //Aux
    public static class ChangeRequest {
        private AuthToken tokenData;
        private RegisterData registerData;
        private ChangePassword passwordData;
        private WorkSheet workSheetData;

        // getters and setters
        public AuthToken getTokenData() {
            return tokenData;
        }

        public RegisterData getRegisterData() {
            return registerData;
        }

        public ChangePassword getPasswordData() {
            return passwordData;
        }

        public WorkSheet getWorkSheetData() {
            return workSheetData;
        }
    }


    @POST
    @Path("/changeRole")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeRole(ChangeRequest changeRoleRequest) {
        AuthToken tokenData = changeRoleRequest.getTokenData();
        RegisterData registerData = changeRoleRequest.getRegisterData();

        LOG.fine("Attempt to changeRoles user with identifier: " + tokenData.id);

        Transaction txn = datastore.newTransaction();

        try {

            Key loginKey = datastore.newKeyFactory().setKind("Login")
                    .addAncestor(PathElement.of("User", tokenData.id))
                    .newKey(tokenData.id);

            Query<Entity> queryVerify = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                            "SELECT * FROM Login WHERE __key__ = @key AND token_id = @tokenId")
                    .setBinding("key", loginKey)
                    .setBinding("tokenId", tokenData.tokenID)
                    .build();

            QueryResults<Entity> tokenResults = datastore.run(queryVerify);

            if (!tokenResults.hasNext()) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).entity("Token doesn't exist or mismatch. Token id: " + tokenData.tokenID + ". Token user: "
                        + tokenData.id + ".").build();
            }
            Entity token = tokenResults.next();
            if (token.getLong("token_expiration") < System.currentTimeMillis()) {
                datastore.delete(token.getKey());
                return Response.status(Status.FORBIDDEN).entity("Failed to change roles by identifier: " + token.getString("token_id") +
                        ".\n Token expired, do the login again to continue!").build();
            } else {

                Key changerKey = userKeyFactory.newKey(tokenData.id);
                Query<Entity> queryChanger = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", changerKey)
                        .build();
                Entity changer = datastore.run(queryChanger).next();

                Key userKey = userKeyFactory.newKey(registerData.username);
                Query<Entity> queryUser = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", userKey)
                        .build();
                QueryResults<Entity> userResults = datastore.run(queryUser);
                if (userResults.hasNext()) {
                    Entity user = userResults.next();
                    if ((changer.getString("user_role").equals(UsersRole.ADMIN.toString()) && verifyRoleAdminRole(registerData.role)) ||
                            changer.getString("user_role").equals(UsersRole.BACKOFFICE.toString()) && verifyRoleBackOfficeRole(registerData.role, user.getString("user_role"))) {
                        user = Entity.newBuilder(user).set("user_role", registerData.role).build();
                        txn.update(user);
                        txn.commit();
                        LOG.warning("User" + registerData.username + "changed role to :" + registerData.role);
                        return Response.ok(g.toJson(user)).build();
                    } else {
                        txn.rollback();
                        return Response.status(Status.FORBIDDEN).entity(//"Role: " + changer.getString("user_role") +  " the String stored : " + UsersRole.ADMIN +
                                "User " + user.getKey().getName() + " dont have permissions or role doesn't exist: " + registerData.role).build();
                    }
                } else {
                    txn.rollback();
                    return Response.status(Status.FORBIDDEN).entity("User that has being changed doesn't exist: " + registerData.username).build();
                }
            }
        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }


    private boolean verifyRoleAdminRole(String role) {
        return role.equalsIgnoreCase(UsersRole.ADMIN.toString()) || role.equalsIgnoreCase(UsersRole.ENDUSER.toString())
                || role.equalsIgnoreCase(UsersRole.BACKOFFICE.toString()) || role.equalsIgnoreCase(UsersRole.PARTNER.toString());
    }

    private boolean verifyRoleBackOfficeRole(String role, String oldRole) {
        return (role.equalsIgnoreCase(UsersRole.ENDUSER.toString()) || role.equalsIgnoreCase(UsersRole.PARTNER.toString())) &&
                (oldRole.equalsIgnoreCase(UsersRole.ENDUSER.toString()) || oldRole.equalsIgnoreCase(UsersRole.PARTNER.toString()));
    }


    @POST
    @Path("/changeState")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeState(ChangeRequest changeStateRequest) {
        AuthToken tokenData = changeStateRequest.getTokenData();
        RegisterData registerData = changeStateRequest.getRegisterData();

        LOG.fine("Attempt to changeStates user with identifier: " + tokenData.id);

        Transaction txn = datastore.newTransaction();

        try {

            Key loginKey = datastore.newKeyFactory().setKind("Login")
                    .addAncestor(PathElement.of("User", tokenData.id))
                    .newKey(tokenData.id);

            Query<Entity> queryVerify = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                            "SELECT * FROM Login WHERE __key__ = @key AND token_id = @tokenId")
                    .setBinding("key", loginKey)
                    .setBinding("tokenId", tokenData.tokenID)
                    .build();

            QueryResults<Entity> tokenResults = datastore.run(queryVerify);

            if (!tokenResults.hasNext()) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).entity("Token doesn't exist or mismatch. Token id: " + tokenData.tokenID + ". Token user: "
                        + tokenData.id + ".").build();
            }
            Entity token = tokenResults.next();
            if (token.getLong("token_expiration") < System.currentTimeMillis()) {
                datastore.delete(token.getKey());
                return Response.status(Status.FORBIDDEN).entity("Failed to change state by identifier: " + token.getString("token_id") +
                        ".\n Token expired, do the login again to continue!").build();
            } else {

                Key changerKey = userKeyFactory.newKey(tokenData.id);
                Query<Entity> queryChanger = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", changerKey)
                        .build();
                Entity changer = datastore.run(queryChanger).next();

                Key userKey = userKeyFactory.newKey(registerData.username);
                Query<Entity> queryUser = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", userKey)
                        .build();
                QueryResults<Entity> userResults = datastore.run(queryUser);
                if (userResults.hasNext()) {
                    Entity user = userResults.next();
                    if ((changer.getString("user_role").equals(UsersRole.ADMIN.toString()) && verifyRoleAdminState(registerData.state)) ||
                            changer.getString("user_role").equals(UsersRole.BACKOFFICE.toString()) && verifyRoleBackOfficeState(registerData.state, user.getString("user_state"))) {
                        user = Entity.newBuilder(user).set("user_state", registerData.state).build();
                        txn.update(user);
                        txn.commit();
                        LOG.warning("User" + registerData.username + "changed state to :" + registerData.state);
                        return Response.ok(g.toJson(user)).build();
                    } else {
                        txn.rollback();
                        return Response.status(Status.FORBIDDEN).entity(//"Role: " + changer.getString("user_role") +  " the String stored : " + UsersRole.ADMIN +
                                "User " + user.getKey().getName() + " dont have permissions or state doesn't exist: " + registerData.state).build();
                    }
                } else {
                    txn.rollback();
                    return Response.status(Status.FORBIDDEN).entity("User that has being changed doesn't exist: " + registerData.username).build();
                }
            }
        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }


    private boolean verifyRoleAdminState(String state) {
        return state.equalsIgnoreCase(CountState.ATIVADA.toString()) || state.equalsIgnoreCase(CountState.DESATIVADA.toString())
                || state.equalsIgnoreCase(CountState.SUSPENSA.toString());
    }

    private boolean verifyRoleBackOfficeState(String state, String oldState) {
        return state.equalsIgnoreCase(CountState.ATIVADA.toString()) || state.equalsIgnoreCase(CountState.DESATIVADA.toString()) &&
                (oldState.equalsIgnoreCase(CountState.ATIVADA.toString()) || oldState.equalsIgnoreCase(CountState.DESATIVADA.toString()));
    }


    @POST
    @Path("/deleteUser")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response removeUser(ChangeRequest removeUserRequest) {
        AuthToken tokenData = removeUserRequest.getTokenData();
        RegisterData registerData = removeUserRequest.getRegisterData();

        LOG.fine("Attempt to changeStates user with identifier: " + tokenData.id);

        Transaction txn = datastore.newTransaction();

        try {

            Key loginKey = datastore.newKeyFactory().setKind("Login")
                    .addAncestor(PathElement.of("User", tokenData.id))
                    .newKey(tokenData.id);

            Query<Entity> queryVerify = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                            "SELECT * FROM Login WHERE __key__ = @key AND token_id = @tokenId")
                    .setBinding("key", loginKey)
                    .setBinding("tokenId", tokenData.tokenID)
                    .build();

            QueryResults<Entity> tokenResults = datastore.run(queryVerify);

            if (!tokenResults.hasNext()) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).entity("Token doesn't exist or mismatch. Token id: " + tokenData.tokenID + ". Token user: "
                        + tokenData.id + ".").build();
            }
            Entity token = tokenResults.next();
            if (token.getLong("token_expiration") < System.currentTimeMillis()) {
                datastore.delete(token.getKey());
                return Response.status(Status.FORBIDDEN).entity("Failed to change state by identifier: " + token.getString("token_id") +
                        ".\n Token expired, do the login again to continue!").build();
            } else {

                Key changerKey = userKeyFactory.newKey(tokenData.id);
                Query<Entity> queryChanger = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", changerKey)
                        .build();
                Entity changer = datastore.run(queryChanger).next();

                Query<Entity> queryUser;
                if (registerData.username != null) {
                    Key userKey = userKeyFactory.newKey(registerData.username);
                    queryUser = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                    "SELECT * FROM User WHERE __key__ = @username")
                            .setBinding("username", userKey)
                            .build();

                } else {
                    queryUser = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                    "SELECT * FROM User WHERE user_email = @email")
                            .setBinding("email", registerData.email)
                            .build();

                }
                QueryResults<Entity> userResults = datastore.run(queryUser);

                if (userResults.hasNext()) {
                    Entity user = userResults.next();
                    if (changer.getString("user_role").equals(UsersRole.ADMIN.toString()) ||
                            (changer.getString("user_role").equals(UsersRole.BACKOFFICE.toString()) && verifyRoleBackOfficeDelete(user.getString("user_role")))) {

                        Key userKey = user.getKey();

                        Key loginUserKey = datastore.newKeyFactory().setKind("Login")
                                .addAncestor(PathElement.of("User", userKey.getName()))
                                .newKey(userKey.getName());

                        txn.delete(loginUserKey);  // Apagar o login

                        txn.delete(user.getKey());
                        txn.commit();
                        LOG.warning("User" + user.getKey().getName() + " has been deleted.");
                        return Response.ok(g.toJson(user)).build();
                    } else {
                        txn.rollback();
                        return Response.status(Status.FORBIDDEN).entity(//"Role: " + changer.getString("user_role") +  " the String stored : " + UsersRole.ADMIN +
                                "User " + changer.getKey().getName() + " don't have permissions to do this operation").build();
                    }
                } else {
                    txn.rollback();
                    return Response.status(Status.FORBIDDEN).entity("User that has being changed doesn't exist.").build();
                }
            }
        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    private boolean verifyRoleBackOfficeDelete(String role) {
        return (role.equalsIgnoreCase(UsersRole.ENDUSER.toString()) || role.equalsIgnoreCase(UsersRole.PARTNER.toString()));
    }

    @POST
    @Path("/users")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUsersInformation(AuthToken tokenData) {
        LOG.fine("Attempt to changeStates user with identifier: " + tokenData.id);

        Transaction txn = datastore.newTransaction();

        try {

            Key loginKey = datastore.newKeyFactory().setKind("Login")
                    .addAncestor(PathElement.of("User", tokenData.id))
                    .newKey(tokenData.id);

            Query<Entity> queryVerify = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                            "SELECT * FROM Login WHERE __key__ = @key AND token_id = @tokenId")
                    .setBinding("key", loginKey)
                    .setBinding("tokenId", tokenData.tokenID)
                    .build();

            QueryResults<Entity> tokenResults = datastore.run(queryVerify);

            if (!tokenResults.hasNext()) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).entity("Token doesn't exist or mismatch. Token id: " + tokenData.tokenID + ". Token user: "
                        + tokenData.id + ".").build();
            }
            Entity token = tokenResults.next();
            if (token.getLong("token_expiration") < System.currentTimeMillis()) {
                datastore.delete(token.getKey());
                return Response.status(Status.FORBIDDEN).entity("Failed to list users by identifier: " + token.getString("token_id") +
                        ".\n Token expired, do the login again to continue!").build();
            } else {

                Key curiousKey = userKeyFactory.newKey(tokenData.id);
                Query<Entity> queryCurious = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", curiousKey)
                        .build();
                Entity curious = datastore.run(queryCurious).next();

                Query<Entity> query;
                List<String> userInfo = new ArrayList<String>();
                if (curious.getString("user_role").equals(UsersRole.ENDUSER.toString())) {
                    query = Query.newEntityQueryBuilder()
                            .setKind("User")
                            .setFilter(
                                    CompositeFilter.and(
                                            PropertyFilter.eq("user_role", "ENDUSER"),
                                            PropertyFilter.eq("user_state", "ATIVADA"),
                                            PropertyFilter.eq("user_status", "público")
                                    )
                            )
                            .build();

                    QueryResults<Entity> users = datastore.run(query);
                    users.forEachRemaining(user -> {
                        String username = user.getKey().getName();
                        String email = user.contains("user_email") ? user.getString("user_email") : "“NOT DEFINED”";
                        String nome = user.contains("user_fullName") ? user.getString("user_fullName") : "“NOT DEFINED”";

                        String userSummary = String.format("Username: %s, Email: %s, Nome: %s", username, email, nome);
                        userInfo.add(userSummary);
                    });

                    return Response.ok(g.toJson(userInfo)).build();
                } else if (curious.getString("user_role").equals(UsersRole.BACKOFFICE.toString())) {
                    query = Query.newEntityQueryBuilder()
                            .setKind("User")
                            .setFilter(
                                    CompositeFilter.and(
                                            PropertyFilter.eq("user_role", "ENDUSER")
                                    )
                            )
                            .build();

                    QueryResults<Entity> users = datastore.run(query);
                    users.forEachRemaining(user -> {
                        String username = user.getKey().getName();
                        String email = user.contains("user_email") ? user.getString("user_email") : "NOT DEFINED";
                        String role = user.contains("user_role") ? user.getString("user_role") : "NOT DEFINED";
                        String nome = user.contains("user_fullName") ? user.getString("user_fullName") : "NOT DEFINED";
                        String phone = user.contains("user_phone") ? user.getString("user_phone") : "NOT DEFINED";
                        String status = user.contains("user_status") ? user.getString("user_status") : "NOT DEFINED";
                        String cc = user.contains("user_cc") ? user.getString("user_cc") : "NOT DEFINED";
                        String NIF = user.contains("user_nif") ? user.getString("user_nif") : "NOT DEFINED";
                        String employer = user.contains("user_employer") ? user.getString("user_employer") : "NOT DEFINED";
                        String function = user.contains("user_function") ? user.getString("user_function") : "NOT DEFINED";
                        String address = user.contains("user_address") ? user.getString("user_address") : "NOT DEFINED";
                        String employerNIF = user.contains("user_employerNif") ? user.getString("user_employerNif") : "NOT DEFINED";

                        String userSummary = String.format(
                                "Username: %s | Email: %s | Nome: %s | Role: %s | Telefone: %s | Status: %s | CC: %s | NIF: %s | Empregador: %s | Função: %s | Morada: %s | NIF Empregador: %s",
                                username, email, nome, role, phone, status, cc, NIF, employer, function, address, employerNIF
                        );
                        userInfo.add(userSummary);
                    });

                    return Response.ok(g.toJson(userInfo)).build();

                } else if (curious.getString("user_role").equals(UsersRole.ADMIN.toString())) {

                    query = Query.newEntityQueryBuilder()
                            .setKind("User")
                            .build();

                    QueryResults<Entity> users = datastore.run(query);
                    users.forEachRemaining(user -> {
                        String username = user.getKey().getName();
                        String pwd = user.contains("user_pwd") ? user.getString("user_pwd") : "NOT DEFINED";
                        String email = user.contains("user_email") ? user.getString("user_email") : "NOT DEFINED";
                        String role = user.contains("user_role") ? user.getString("user_role") : "NOT DEFINED";
                        String nome = user.contains("user_fullName") ? user.getString("user_fullName") : "NOT DEFINED";
                        String phone = user.contains("user_phone") ? user.getString("user_phone") : "NOT DEFINED";
                        String status = user.contains("user_status") ? user.getString("user_status") : "NOT DEFINED";
                        String cc = user.contains("user_cc") ? user.getString("user_cc") : "NOT DEFINED";
                        String NIF = user.contains("user_nif") ? user.getString("user_nif") : "NOT DEFINED";
                        String employer = user.contains("user_employer") ? user.getString("user_employer") : "NOT DEFINED";
                        String function = user.contains("user_function") ? user.getString("user_function") : "NOT DEFINED";
                        String address = user.contains("user_address") ? user.getString("user_address") : "NOT DEFINED";
                        String employerNIF = user.contains("user_employerNif") ? user.getString("user_employerNif") : "NOT DEFINED";

                        String userSummary = String.format(
                                "Username: %s | Password: %s |Email: %s | Nome: %s | Role: %s | Telefone: %s | Status: %s | CC: %s | NIF: %s | Empregador: %s | Função: %s | Morada: %s | NIF Empregador: %s",
                                username, pwd, email, nome, role, phone, status, cc, NIF, employer, function, address, employerNIF
                        );
                        userInfo.add(userSummary);
                    });

                    return Response.ok(g.toJson(userInfo)).build();

                } else {
                    txn.rollback();
                    return Response.status(Status.FORBIDDEN).entity("User don't have permission to this!!").build();
                }
            }


        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }


    @POST
    @Path("/changeAttributes")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeAttributes(ChangeRequest changeAttributesRequest) {
        AuthToken tokenData = changeAttributesRequest.getTokenData();
        RegisterData registerData = changeAttributesRequest.getRegisterData();

        LOG.fine("Attempt to changeAttributes user with identifier: " + tokenData.id);

        Transaction txn = datastore.newTransaction();

        try {

            Key loginKey = datastore.newKeyFactory().setKind("Login")
                    .addAncestor(PathElement.of("User", tokenData.id))
                    .newKey(tokenData.id);

            Query<Entity> queryVerify = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                            "SELECT * FROM Login WHERE __key__ = @key AND token_id = @tokenId")
                    .setBinding("key", loginKey)
                    .setBinding("tokenId", tokenData.tokenID)
                    .build();

            QueryResults<Entity> tokenResults = datastore.run(queryVerify);

            if (!tokenResults.hasNext()) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).entity("Token doesn't exist or mismatch. Token id: " + tokenData.tokenID + ". Token user: "
                        + tokenData.id + ".").build();
            }
            Entity token = tokenResults.next();
            if (token.getLong("token_expiration") < System.currentTimeMillis()) {
                datastore.delete(token.getKey());
                return Response.status(Status.FORBIDDEN).entity("Failed to change state by identifier: " + token.getString("token_id") +
                        ".\n Token expired, do the login again to continue!").build();
            } else {

                Key changerKey = userKeyFactory.newKey(tokenData.id);
                Query<Entity> queryChanger = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", changerKey)
                        .build();
                Entity changer = datastore.run(queryChanger).next();

                Key userKey = userKeyFactory.newKey(registerData.username);
                Query<Entity> queryUser = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", userKey)
                        .build();
                QueryResults<Entity> userResults = datastore.run(queryUser);
                if (userResults.hasNext()) {
                    Entity user = userResults.next();

                    if (changer.getString("user_role").equals(UsersRole.ENDUSER.toString())) {
                        if (changer.getKey().equals(userKey)) {
                            if (changer.getString("user_state").equals(CountState.ATIVADA.toString())) {
                                if (correctStatusFormat(registerData)) {
                                    user = changeAttributes(user, registerData);
                                    txn.update(user);
                                    txn.commit();
                                    LOG.warning("User" + registerData.username + " information has been updated!");
                                    return Response.ok(g.toJson(user)).build();
                                } else {
                                    txn.rollback();
                                    return Response.status(Status.FORBIDDEN).entity("Information sent is not in the correct format!!").build();
                                }
                            } else {
                                txn.rollback();
                                return Response.status(Status.FORBIDDEN).entity("ENDUSER User " + changer.getKey().getName() + " is not active!").build();
                            }
                        } else {
                            txn.rollback();
                            return Response.status(Status.FORBIDDEN).entity("ENDUSER User can only change the information about his account!").build();
                        }
                    } else if (changer.getString("user_role").equals(UsersRole.BACKOFFICE.toString())) {
                        if (changer.getString("user_state").equals(CountState.ATIVADA.toString())) {
                            if (user.getString("user_role").equals(UsersRole.ENDUSER.toString()) || user.getString("user_role").equals(UsersRole.PARTNER.toString())) {
                                if (roleAndStateCorrectBackOffice(registerData) && correctStatusFormat(registerData)) {
                                    user = changeAttributes(user, registerData);
                                    user = changeRolesStates(user, registerData);
                                    txn.update(user);
                                    txn.commit();
                                    LOG.warning("User" + registerData.username + " information has been updated!");
                                    return Response.ok(g.toJson(user)).build();
                                } else {
                                    txn.rollback();
                                    return Response.status(Status.FORBIDDEN).entity("Information sent is not in the correct format!!").build();
                                }
                            } else {
                                txn.rollback();
                                return Response.status(Status.FORBIDDEN).entity("BACKOFFICE User " + changer.getKey().getName() + " cannot change this account information!").build();
                            }
                        } else {
                            txn.rollback();
                            return Response.status(Status.FORBIDDEN).entity("BACKOFFICE User " + changer.getKey().getName() + " is not active!").build();
                        }

                    } else if (changer.getString("user_role").equals(UsersRole.ADMIN.toString())) {
                        if (roleAndStateCorrectAdmin(registerData) && correctStatusFormat(registerData)) {
                            user = changeAttributes(user, registerData);
                            user = changeRolesStates(user, registerData);
                            user = changeInformationAdmin(user, registerData);
                            txn.update(user);
                            txn.commit();
                            LOG.warning("User" + registerData.username + " information has been updated!");
                            return Response.ok(g.toJson(user)).build();
                        } else {
                            txn.rollback();
                            return Response.status(Status.FORBIDDEN).entity("Information sent is not in the correct format!!").build();
                        }
                    } else {
                        txn.rollback();
                        return Response.status(Status.FORBIDDEN).entity("User cannot use this operation!!").build();
                    }
                } else {
                    txn.rollback();
                    return Response.status(Status.FORBIDDEN).entity("User that has being changed doesn't exist: " + registerData.username).build();
                }
            }
        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }


    private Entity changeAttributes(Entity user, RegisterData data) {
        if (data.phone != null) {
            user = Entity.newBuilder(user).set("user_phone", data.phone).build();
        }
        if (data.status != null) {
            user = Entity.newBuilder(user).set("user_status", data.status).build();
        }
        if (data.cc != null) {
            user = Entity.newBuilder(user).set("user_cc", data.cc).build();
        }
        if (data.NIF != null) {
            user = Entity.newBuilder(user).set("user_nif", data.NIF).build();
        }
        if (data.employer != null) {
            user = Entity.newBuilder(user).set("user_employer", data.employer).build();
        }
        if (data.function != null) {
            user = Entity.newBuilder(user).set("user_function", data.function).build();
        }
        if (data.address != null) {
            user = Entity.newBuilder(user).set("user_address", data.address).build();
        }
        if (data.employerNIF != null) {
            user = Entity.newBuilder(user).set("user_employerNif", data.employerNIF).build();
        }

        return user;
    }

    private boolean correctStatusFormat(RegisterData data) {
        if (data.status == null) return true; //
        String status = data.status.trim().toLowerCase();
        return status.equals("público") || status.equals("privado");
    }

    private boolean roleAndStateCorrectAdmin(RegisterData data) {
        boolean roleValid = true;
        boolean stateValid = true;

        if (data.role != null) {
            String role = data.role.trim().toUpperCase();
            roleValid = role.equals(UsersRole.ENDUSER.toString()) ||
                    role.equals(UsersRole.BACKOFFICE.toString()) ||
                    role.equals(UsersRole.ADMIN.toString()) ||
                    role.equals(UsersRole.PARTNER.toString());
        }

        if (data.state != null) {
            String state = data.state.trim().toUpperCase();
            stateValid = state.equals(CountState.ATIVADA.toString()) ||
                    state.equals(CountState.SUSPENSA.toString()) ||
                    state.equals(CountState.DESATIVADA.toString());
        }

        return roleValid && stateValid;
    }

    private boolean roleAndStateCorrectBackOffice(RegisterData data) {

        boolean roleValid = true;
        boolean stateValid = true;

        if (data.role != null) {
            String role = data.role.trim().toUpperCase();
            roleValid = role.equals(UsersRole.ENDUSER.toString()) ||
                    role.equals(UsersRole.PARTNER.toString());
        }

        if (data.state != null) {
            String state = data.state.trim().toUpperCase();
            stateValid = state.equals(CountState.ATIVADA.toString()) ||
                    state.equals(CountState.DESATIVADA.toString());
        }

        return roleValid && stateValid;
    }

    private Entity changeRolesStates(Entity user, RegisterData data) {
        if (data.role != null) {
            user = Entity.newBuilder(user).set("user_role", data.role).build();
        }
        if (data.state != null) {
            user = Entity.newBuilder(user).set("user_state", data.state).build();
        }
        return user;
    }

    private Entity changeInformationAdmin(Entity user, RegisterData data) {
        if (data.email != null) {
            user = Entity.newBuilder(user).set("user_email", data.email).build();
        }
        if (data.fullName != null) {
            user = Entity.newBuilder(user).set("user_fullName", data.fullName).build();
        }
        return user;
    }


    @POST
    @Path("/changePassword")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changePassword(ChangeRequest changePasswordRequest) {
        AuthToken tokenData = changePasswordRequest.getTokenData();
        ChangePassword passwordData = changePasswordRequest.getPasswordData();

        LOG.fine("Attempt to change password user with identifier: " + tokenData.id);

        Transaction txn = datastore.newTransaction();

        try {

            Key loginKey = datastore.newKeyFactory().setKind("Login")
                    .addAncestor(PathElement.of("User", tokenData.id))
                    .newKey(tokenData.id);

            Query<Entity> queryVerify = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                            "SELECT * FROM Login WHERE __key__ = @key AND token_id = @tokenId")


                    .setBinding("key", loginKey)
                    .setBinding("tokenId", tokenData.tokenID)
                    .build();

            QueryResults<Entity> tokenResults = datastore.run(queryVerify);

            if (!tokenResults.hasNext()) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).entity("Token doesn't exist or mismatch. Token id: " + tokenData.tokenID + ". Token user: "
                        + tokenData.id + ".").build();
            }
            Entity token = tokenResults.next();
            if (token.getLong("token_expiration") < System.currentTimeMillis()) {
                datastore.delete(token.getKey());
                return Response.status(Status.FORBIDDEN).entity("Failed to change state by identifier: " + token.getString("token_id") +
                        ".\n Token expired, do the login again to continue!").build();
            } else {

                Key changerKey = userKeyFactory.newKey(tokenData.id);
                Query<Entity> queryChanger = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", changerKey)
                        .build();
                Entity changer = datastore.run(queryChanger).next();

                if (changer.getString("user_pwd").equals(DigestUtils.sha512Hex(passwordData.oldPwd))) {

                    if (passwordData.validChangePassword()) {
                        changer = Entity.newBuilder(changer).set("user_pwd", DigestUtils.sha512Hex(passwordData.newPwd)).build();
                        txn.update(changer);
                        txn.commit();
                        LOG.warning("User" + changer.getKey().getName() + " password has been updated!");
                        return Response.ok(g.toJson(changer)).build();

                    } else {
                        txn.rollback();
                        return Response.status(Status.FORBIDDEN).entity("The passwords are not equal").build();
                    }

                } else {
                    txn.rollback();
                    return Response.status(Status.FORBIDDEN).entity("The password is not correct ").build();
                }
            }
        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

    @POST
    @Path("/logout")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getLoggedOut(AuthToken tokenData) {
        LOG.fine("Attempt to changeStates user with identifier: " + tokenData.id);

        Transaction txn = datastore.newTransaction();

        try {

            Key loginKey = datastore.newKeyFactory().setKind("Login")
                    .addAncestor(PathElement.of("User", tokenData.id))
                    .newKey(tokenData.id);

            Query<Entity> queryVerify = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                            "SELECT * FROM Login WHERE __key__ = @key AND token_id = @tokenId")
                    .setBinding("key", loginKey)
                    .setBinding("tokenId", tokenData.tokenID)
                    .build();

            QueryResults<Entity> tokenResults = datastore.run(queryVerify);

            if (!tokenResults.hasNext()) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).entity("Token doesn't exist or mismatch. Token id: " + tokenData.tokenID + ". Token user: "
                        + tokenData.id + ".").build();

            } else {
                Entity token = tokenResults.next();
                datastore.delete(token.getKey());
                LOG.warning("User" + token.getKey().getName() + " logout sucessfully!");
                return Response.ok().build();
            }

        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }


    @POST
    @Path("/worksheet")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response accessWorkSheet(ChangeRequest changeAttributesRequest) {
        AuthToken tokenData = changeAttributesRequest.getTokenData();
        WorkSheet workSheetData = changeAttributesRequest.getWorkSheetData();

        LOG.fine("Attempt to changeAttributes user with identifier: " + tokenData.id);

        Transaction txn = datastore.newTransaction();

        try {

            Key loginKey = datastore.newKeyFactory().setKind("Login")
                    .addAncestor(PathElement.of("User", tokenData.id))
                    .newKey(tokenData.id);

            Query<Entity> queryVerify = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                            "SELECT * FROM Login WHERE __key__ = @key AND token_id = @tokenId")
                    .setBinding("key", loginKey)
                    .setBinding("tokenId", tokenData.tokenID)
                    .build();

            QueryResults<Entity> tokenResults = datastore.run(queryVerify);

            if (!tokenResults.hasNext()) {
                txn.rollback();
                return Response.status(Status.FORBIDDEN).entity("Token doesn't exist or mismatch. Token id: " + tokenData.tokenID + ". Token user: "
                        + tokenData.id + ".").build();
            }
            Entity token = tokenResults.next();
            if (token.getLong("token_expiration") < System.currentTimeMillis()) {
                datastore.delete(token.getKey());
                return Response.status(Status.FORBIDDEN).entity("Failed to change state by identifier: " + token.getString("token_id") +
                        ".\n Token expired, do the login again to continue!").build();
            } else {

                Key userKey = userKeyFactory.newKey(tokenData.id);
                Query<Entity> queryChanger = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE __key__ = @username")
                        .setBinding("username", userKey)
                        .build();
                Entity user = datastore.run(queryChanger).next();


                if (user.getString("user_role").equals(UsersRole.BACKOFFICE.toString())) {

                    Key workSheetKey = datastore.newKeyFactory().setKind("WorkSheet").newKey(workSheetData.reference);
                    Entity workSheet = txn.get(workSheetKey);

                    if (workSheet != null) {
                        if (workSheetData.validRegistration()) {
                            workSheet = Entity.newBuilder(workSheetKey)
                                    .set("workSheet_description", workSheetData.description)
                                    .set("workSheet_workType", workSheetData.workType).set("workSheet_adjudicationState", workSheetData.adjudicationState)
                                    .build();
                            txn.update(workSheet);
                            txn.commit();
                            LOG.warning("WorkSheet" + workSheetData.reference + " has been updated!");
                            return Response.ok(g.toJson(workSheet)).build();
                        } else {
                            txn.rollback();
                            return Response.status(Status.FORBIDDEN).entity("The information sent is not in the correct format. Try again").build();
                        }
                    } else {
                        if (workSheetData.validRegistration() && workSheetData.invalidRegistration()) {
                            workSheet = Entity.newBuilder(workSheetKey)
                                    .set("workSheet_description", workSheetData.description)
                                    .set("workSheet_workType", workSheetData.workType).set("workSheet_adjudicationState", workSheetData.adjudicationState)
                                    .build();
                            txn.put(workSheet);
                            txn.commit();
                            LOG.warning("WorkSheet" + workSheetData.reference + " has been saved! ");
                            return Response.ok(g.toJson(workSheet)).build();
                        } else {
                            txn.rollback();
                            return Response.status(Status.FORBIDDEN).entity("The information sent is not in the correct format. Try again").build();
                        }
                    }

                } else if (user.getString("user_role").equals(UsersRole.PARTNER.toString())) {

                    Key workSheetKey = datastore.newKeyFactory().setKind("WorkSheet").newKey(workSheetData.reference);
                    Entity workSheet = txn.get(workSheetKey);
                    if (workSheet != null) {
                        if (workSheetData.hasOnlyAdjudicationData()) {
                            if (!workSheet.getNames().contains("workSheet_entity")) {
                                if (workSheet.getString("workSheet_adjudicationState").equals("ADJUDICADO")) {
                                    workSheet = Entity.newBuilder(workSheet)
                                            .set("workSheet_adjudicationDate", workSheetData.adjudicationDate)
                                            .set("workSheet_workStartDate", workSheetData.workStartDate).set("workSheet_workEndDate", workSheetData.workEndDate)
                                            .set("workSheet_entity", user.getKey().getName()).set("workSheet_employerNIF", workSheetData.employerNIF)
                                            .set("workSheet_workState", workSheetData.workState).set("workSheet_observations", workSheetData.observations)
                                            .build();
                                    txn.update(workSheet);
                                    txn.commit();
                                    LOG.warning("WorkSheet" + workSheetData.reference + " has been updated!");
                                    return Response.ok(g.toJson(workSheet)).build();
                                } else {
                                    txn.rollback();
                                    return Response.status(Status.FORBIDDEN).entity("The worksheet is not been adjudicate.").build();
                                }
                            } else {
                                txn.rollback();
                                return Response.status(Status.FORBIDDEN).entity("The WorkSheet with the reference " + workSheetData.reference + " has already been modified by " +
                                        "other user.").build();
                            }
                        } else {
                            txn.rollback();
                            return Response.status(Status.FORBIDDEN).entity("The information sent isn't in the correct format").build();
                        }
                    } else {
                        txn.rollback();
                        return Response.status(Status.FORBIDDEN).entity("The WorkSheet with the reference " + workSheetData.reference + " doesn't exist.").build();
                    }

                } else {
                    txn.rollback();
                    return Response.status(Status.FORBIDDEN).entity("User don't have permissions to access this operation. \n"
                            + "User role is: " + user.getString("user_role") + ".").build();
                }

            }
        } catch (DatastoreException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.toString()).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }

    }
}







