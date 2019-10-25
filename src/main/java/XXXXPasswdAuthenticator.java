import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hive.service.auth.PasswdAuthenticationProvider;

import javax.security.sasl.AuthenticationException;


public class XXXXPasswdAuthenticator implements PasswdAuthenticationProvider, Configurable {
	private static final Log LOG=LogFactory.getLog(XXXXPasswdAuthenticator.class);
	private Configuration conf=null;
	
	private static final String HIVE_JDBC_PASSWD_AUTH_PREFIX="hive.jdbc_passwd.auth.%s";
	
	public XXXXPasswdAuthenticator() {
		init();
	}
	
	/**
	 * 
	 */
	public void init(){
		
	}
	
	public void Authenticate(String userName, String passwd)
			throws AuthenticationException {
		LOG.info("user: "+userName+" passwd: "+passwd+" try login.");

		String passwdMD5 = getConf().get(String.format(HIVE_JDBC_PASSWD_AUTH_PREFIX, userName));
		LOG.info("passwdMD5:"+passwdMD5);
		if(passwdMD5==null){
			String message = "user's ACL configration is not found. user:"+userName;
			LOG.info(message);
			throw new AuthenticationException(message);
		}
		
		String md5 = MD5Util.textToMD5L32(passwd);
		LOG.info("md5:"+md5);
		if(!md5.equals(passwdMD5)){
			String message = "user name and password is mismatch. user:"+userName;
			throw new AuthenticationException(message);
		}
		
		LOG.info("user "+userName+" login system successfully.");
		
	}

	public Configuration getConf() {
		if(conf==null){
			this.conf=new Configuration();
		}
		
		return conf;
	}

	public void setConf(Configuration arg0) {
		this.conf=arg0;
	}

}