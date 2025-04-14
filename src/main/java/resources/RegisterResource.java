package resources;

import java.util.logging.Logger;

import Enums.CountState;
import Enums.UsersRole;
import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.google.gson.Gson;

import com.google.cloud.Timestamp;

import jakarta.ws.rs.core.Response.Status;
import util.LoginData;
import util.RegisterData;

@Path("/register")
public class RegisterResource {

    private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    private final Gson g = new Gson();


    public RegisterResource() {
    }    // Default constructor, nothing to do


    @POST
    @Path("/v3")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response registerUserV3(RegisterData data) {
        LOG.fine("Attempt to register user: " + data.username);

        if (!data.validRegistration()) {
            return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameter.").build();
        }

        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
            Entity user = txn.get(userKey);


            // If the entity does not exist null is returned...
            if (user != null) {
                txn.rollback();
                return Response.status(Status.CONFLICT).entity("User already exists.").build();
            } else {

                Query<Entity> query = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
                                "SELECT * FROM User WHERE user_email = @email")
                        .setBinding("email", data.email)
                        .build();

                QueryResults<Entity> results = datastore.run(query);
                if (results.hasNext()) {
                    txn.rollback();
                    return Response.status(Status.CONFLICT).entity("User already exists.").build();
                } else {


                    // ... otherwise
                    user = Entity.newBuilder(userKey).set("user_fullName", data.fullName)
                            .set("user_pwd", DigestUtils.sha512Hex(data.password)).set("user_email", data.email)
                            .set("user_phone", data.phone).set("user_status", data.status)
                            .set("user_role", UsersRole.ENDUSER.toString()).set("user_state", CountState.DESATIVADA.toString())
                            .build();


                    // get() followed by put() inside a transaction is ok...

                    if (data.cc != null) {
                        user = Entity.newBuilder(user).set("user_cc", data.cc).build();
                    } else user = Entity.newBuilder(user).setNull("user_cc").build();
                    if (data.NIF != null) {
                        user = Entity.newBuilder(user).set("user_nif", data.NIF).build();
                    } else user = Entity.newBuilder(user).setNull("nif").build();
                    if (data.employer != null) {
                        user = Entity.newBuilder(user).set("user_employer", data.employer).build();
                    } else user = Entity.newBuilder(user).setNull("user_employer").build();
                    if (data.function != null) {
                        user = Entity.newBuilder(user).set("user_function", data.function).build();
                    } else user = Entity.newBuilder(user).setNull("user_function").build();
                    if (data.address != null) {
                        user = Entity.newBuilder(user).set("user_address", data.address).build();
                    } else user = Entity.newBuilder(user).setNull("user_address").build();
                    if (data.employerNIF != null) {
                        user = Entity.newBuilder(user).set("user_employerNif", data.employerNIF).build();
                    } else user = Entity.newBuilder(user).setNull("user_employerNif").build();


                    user = Entity.newBuilder(user).set("user_creation_time", Timestamp.now()).build();

                    txn.put(user);
                    txn.commit();
                    LOG.info("User registered " + data.username);
                    return Response.ok(g.toJson(user)).build();
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