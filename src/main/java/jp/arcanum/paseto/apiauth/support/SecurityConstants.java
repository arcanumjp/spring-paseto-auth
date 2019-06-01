package jp.arcanum.paseto.apiauth.support;

import net.aholbrook.paseto.service.PublicTokenService.KeyProvider;
import net.aholbrook.paseto.util.Hex;

public class SecurityConstants {
    public static final String SECRET = "nyasbasamplesecret";
    public static final long EXPIRATION_TIME = 28_800_000; // 8hours
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String SIGNUP_URL = "/user/signup";
    public static final String LOGIN_URL = "/user/login";
    public static final String LOGIN_ID = "loginId"; // defalut:username
    public static final String PASSWORD = "pass"; // default:password
    
    // get from RFCTestVectors
	public static byte[] RFC_TEST_SK = Hex.decode("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a377"
			+ "41eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");
	public static byte[] RFC_TEST_PK = Hex.decode("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a"
			+ "2");

	public static KeyProvider PROVIDER = new KeyProvider() {
		@Override
		public byte[] getSecretKey() {
			return RFC_TEST_SK;
		}
		@Override
		public byte[] getPublicKey() {
			return RFC_TEST_PK;
		}
	};
	
}