package mypackage;

import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import org.jboss.resteasy.annotations.interception.Precedence;
import org.jboss.resteasy.annotations.interception.ServerInterceptor;
import org.jboss.resteasy.core.Headers;
import org.jboss.resteasy.core.ResourceMethod;
import org.jboss.resteasy.core.ServerResponse;
import org.jboss.resteasy.spi.Failure;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.UnauthorizedException;
import org.jboss.resteasy.spi.interception.PreProcessInterceptor;
import org.jboss.resteasy.util.HttpResponseCodes;

import com.google.gson.JsonObject;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.Mongo;
import com.mongodb.MongoException;
import com.google.gson.Gson;



@Provider
@ServerInterceptor
public class RestSecurityInterceptor implements PreProcessInterceptor {

    @Override
    public ServerResponse preProcess(HttpRequest request, ResourceMethod method) 
           throws UnauthorizedException {
    	//return null;
    	System.out.println(method.getMethod().toString());
    	Mongo mongo = null;
    	try {	
    	if(!method.getMethod().toString().contains("delete_usercrop") && !method.getMethod().toString().contains("updateusercrop") && !method.getMethod().toString().contains("adduser") && !method.getMethod().toString().contains("authenticate") && !method.getMethod().toString().contains("isUserAvailable"))
   	{
    		System.out.println(method.getMethod().toString());
    		
    	String username = request.getHttpHeaders().getRequestHeader("username").get(0);
    	System.out.println(username);
    	String secretKey = request.getHttpHeaders().getRequestHeader("secretKey").get(0);
    	//String secretKey ="as";
    	
    	DB db;
		//Mongo mongo;
	//	try {
			//mongo = new Mongo("localhost", 27017);
			
			
		mongo = new Mongo("127.3.119.1", 27017);
			
		db = mongo.getDB("gardenshift");
		db.authenticate("admin", "redhat".toCharArray());
		
		
    	DBCollection collection = db.getCollection("users");
        BasicDBObject getTimestamp = new BasicDBObject();
        getTimestamp.put("username", username);

        BasicDBObject keys = new BasicDBObject();
        keys.put("login_timestamp" ,1 );
         DBCursor cursor = collection.find( getTimestamp, keys);
        
        String ts = "";
        while (cursor.hasNext()) {
        	ts=cursor.next().get("login_timestamp").toString();

    		}
        if(hashGen(username+ts).equals(secretKey))
        		{
        	return null;
        }
        else {
        	
        	System.out.println("1");
    		ServerResponse response = new ServerResponse();
            response.setStatus(HttpResponseCodes.SC_UNAUTHORIZED);
            MultivaluedMap<String, Object> headers = new Headers<Object>();
            headers.add("Content-Type", "text/plain");
            response.setMetadata(headers);
            response.setEntity("Error 401 Unauthorized: " 
                 + request.getPreprocessedPath());
            return response;
        }
        } 
    	else return null;
    	} catch (UnknownHostException e) {
    		System.out.println("1");
    		ServerResponse response = new ServerResponse();
            response.setStatus(HttpResponseCodes.SC_UNAUTHORIZED);
            MultivaluedMap<String, Object> headers = new Headers<Object>();
            headers.add("Content-Type", "text/plain");
            response.setMetadata(headers);
            response.setEntity("Error 401 Unauthorized: " 
                 + request.getPreprocessedPath());
            return response;
		} catch (MongoException e) {
			System.out.println("1");
    		ServerResponse response = new ServerResponse();
            response.setStatus(HttpResponseCodes.SC_UNAUTHORIZED);
            MultivaluedMap<String, Object> headers = new Headers<Object>();
            headers.add("Content-Type", "text/plain");
            response.setMetadata(headers);
            response.setEntity("Error 401 Unauthorized: " 
                 + request.getPreprocessedPath());
            return response;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("1");
    		ServerResponse response = new ServerResponse();
            response.setStatus(HttpResponseCodes.SC_UNAUTHORIZED);
            MultivaluedMap<String, Object> headers = new Headers<Object>();
            headers.add("Content-Type", "text/plain");
            response.setMetadata(headers);
            response.setEntity("Error 401 Unauthorized: " 
                 + request.getPreprocessedPath());
            return response;
		}
    	finally {
    		if(mongo!=null)
    		mongo.close();
    	}
  	
    	
		
    }
//    	 return null;
    		
//    	return null;}else
//    	{
//    		return null;
//    	}
//}

	private static String hashGen(String string) throws NoSuchAlgorithmException {
		byte[] buffer = string.getBytes();  
		   
		
		    MessageDigest md = MessageDigest.getInstance("SHA-1"); 
		   
		    Formatter formatter = new Formatter();
		    for (byte b : md.digest(buffer)) {
		        formatter.format("%02x", b);
		    }
		    return formatter.toString();
		

	}
   }
