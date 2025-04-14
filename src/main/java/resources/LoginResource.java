package resources;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.StructuredQuery.CompositeFilter;
import com.google.cloud.datastore.StructuredQuery.OrderBy;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.gson.Gson;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response.Status;
import org.apache.http.util.EntityUtils;
import util.AuthToken;
import util.LoginData;


@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

	private static final String MESSAGE_INVALID_CREDENTIALS = "Incorrect username or password.";

	private static final String MESSAGE_NEXT_PARAMETER_INVALID = "Request parameter 'next' must be greater or equal to 0.";

	private static final String LOG_MESSAGE_LOGIN_ATTEMP = "Login attempt by user: ";
	private static final String LOG_MESSAGE_LOGIN_SUCCESSFUL = "Login successful by user: ";
	private static final String LOG_MESSAGE_WRONG_PASSWORD = "Wrong password for: ";
	private static final String LOG_MESSAGE_UNKNOW_USER = "Failed login attempt for username: ";

	private static final String USER_PWD = "user_pwd";
	private static final String USER_LOGIN_TIME = "user_login_time";


	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

	private final Gson g = new Gson();

	public LoginResource() {

	}

	@POST
	@Path("/")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginData data) {
		LOG.fine("Login attempt by user: " + data.id);

		if (data.id.equals("user") && data.password.equals("password")) {
			AuthToken at = new AuthToken(data.id);
			return Response.ok(g.toJson(at)).build();
		}
		return Response.status(Status.FORBIDDEN).entity("Incorrect username/email or password.").build();
	}


	@POST
	@Path("/v1b")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doLoginV1b(LoginData data) {
		LOG.fine("Attempt to login user with identifier: " + data.id);

		Key userKey = userKeyFactory.newKey(data.id);

		Entity user = datastore.get(userKey);

		if (user == null) {
			Query<Entity> query = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
							"SELECT * FROM User WHERE user_email = @id")
					.setBinding("id", data.id)
					.build();

			user = datastore.run(query).next();
		}

		if (user != null) {
			String username = user.getKey().getName();
			String hashedPWD = user.getString("user_pwd");
			if (hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {

				KeyFactory logKeyFactory = datastore.newKeyFactory()
						.addAncestor(PathElement.of("User", username))
						.setKind("UserLog");
				Key logKey = datastore.allocateId(logKeyFactory.newKey());

				Entity userLog = Entity.newBuilder(logKey)
						.set("user_login_time", Timestamp.now())
						.build();
				datastore.put(userLog);

				LOG.info("User '" + username + "' logged in successfuly.");

				AuthToken token = new AuthToken(username);

				KeyFactory loginKeyFactory = datastore.newKeyFactory()
						.addAncestor(PathElement.of("User", username))
						.setKind("Login");

				Key loginKey = loginKeyFactory.newKey(username);

				Query<Entity> query = Query.newGqlQueryBuilder(Query.ResultType.ENTITY,
								"SELECT * FROM Login WHERE toke_user = @id")
						.setBinding("id", token.id)
						.build();

				Entity login;
				QueryResults<Entity> results = datastore.run(query);
				if (results.hasNext()) {
                    login = results.next();
					login = Entity.newBuilder(login.getKey())
							.set("creation_time", token.creationData)
							.set("token_expiration", token.expirationData).set("token_id", token.tokenID)
							.build();
					datastore.update(login);
				}else {
					login = Entity.newBuilder(loginKey)
							.set("creation_time", token.creationData)
							.set("token_expiration", token.expirationData).set("token_id", token.tokenID)
							.build();
					datastore.put(login);
				}



				return Response.ok(g.toJson(token)).build();
			} else {
				LOG.warning("Wrong password for: " + data.id);
				return Response.status(Status.FORBIDDEN).build();
			}
		} else {
			LOG.warning("Failed login attempt for username: " + data.id);
			return Response.status(Status.FORBIDDEN).build();
		}
	}


}