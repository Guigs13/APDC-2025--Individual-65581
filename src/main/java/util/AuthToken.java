package util;

import java.util.UUID;

public class AuthToken {

	public static final long EXPIRATION_TIME = 1000*60*60*2;
	
	public String id;
	public String tokenID;
	public long creationData;
	public long expirationData;
	
	public AuthToken() {

	}
	
	public AuthToken(String id) {
		this.id = id;
		this.tokenID = UUID.randomUUID().toString();
		this.creationData = System.currentTimeMillis();
		this.expirationData = this.creationData + EXPIRATION_TIME;
	}
	
}
