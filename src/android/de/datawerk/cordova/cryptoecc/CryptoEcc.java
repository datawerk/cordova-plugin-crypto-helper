/**
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.datawerk.cordova.cryptoecc;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.jboss.aerogear.crypto.Random;
import org.jboss.aerogear.crypto.password.Pbkdf2;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.neilalexander.jnacl.NaCl;
import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class CryptoEcc extends CordovaPlugin {
	@Override
	public boolean execute(final String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
		
		if ("getRandomValue".equals(action)) {
			final JSONObject params = parseParameters(args);
			final int len = params.has("length") ? params.getInt("length") : 16;
            
			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
					final byte[] bytes = new Random().randomBytes(len);
					callbackContext.success(NaCl.asHex(bytes));
				}
			});
		}
		
		if ("deriveKey".equals(action)) {
			final JSONObject params = parseParameters(args);
			final String password = params.getString("password");
			final byte[] salt = params.has("salt") ? NaCl.getBinary(params.getString("salt")) : null;
            
			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
					Pbkdf2 pbkdf2 = new Pbkdf2();
					try {
						byte[] encryptSalt = salt != null ? salt : new Random().randomBytes();
						byte[] rawPassword = pbkdf2.encrypt(password, encryptSalt);
                        
						callbackContext.success(NaCl.asHex(rawPassword));
					} catch (InvalidKeySpecException e) {
						callbackContext.error(e.getMessage());
					}
				}
			});
		}
        
		if ("validateKey".equals(action)) {
			final JSONObject params = parseParameters(args);
			final String password = params.getString("password");
			final String encryptedPassword = params.getString("encryptedPassword");
			final byte[] salt = NaCl.getBinary(params.getString("salt"));
            
			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
					Pbkdf2 pbkdf2 = new Pbkdf2();
					try {
						boolean valid = pbkdf2.validate(password, NaCl.getBinary(encryptedPassword), salt);
						callbackContext.success(String.valueOf(valid));
					} catch (InvalidKeySpecException e) {
						callbackContext.error(e.getMessage());
					}
				}
			});
		}
		
		if ("generateKeyPair".equals(action)) {
			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
                    
					byte[] pk = new byte[curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES];
					byte[] sk = new byte[curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES];
                    
					SecureRandom rng = new SecureRandom();
					rng.nextBytes(sk);
                    
					curve25519xsalsa20poly1305.crypto_box_keypair(pk, sk);
					final JSONObject object = new JSONObject();
					try {
						object.put("privateKey", NaCl.asHex(pk));
						object.put("publicKey", NaCl.asHex(sk));
					} catch (JSONException e) {
						throw new RuntimeException("could not construct key pair object");
					}
					callbackContext.success(object);
				}
			});
		}
        
		if ("decrypt".equals(action) || "encrypt".equals(action)) {
			JSONObject params = parseParameters(args);
			final String publicKey = (String) params.get("publicKey");
			final String privateKey = (String) params.get("privateKey");
			final byte[] nonce = NaCl.getBinary((String) params.get("nonce"));
			final String data = (String) params.get("data");
            
			cordova.getThreadPool().execute(new Runnable() {
				public void run() {
                    
					NaCl cryptoBox = null;
					try {
						cryptoBox = new NaCl(privateKey, publicKey);
						
						String result = null;
						if ("encrypt".equals(action)) {
							result = NaCl.asHex(cryptoBox.encrypt(data.getBytes(), nonce));
						}
                        
						if ("decrypt".equals(action)) {
							result = new String(cryptoBox.decrypt(NaCl.getBinary(data), nonce));
						}
                        
						callbackContext.success(result);
					} catch (Exception e) {
						callbackContext.success("");
					}
				}
			});
		}
        
		return true;
	}
    
	private JSONObject parseParameters(JSONArray data) throws JSONException {
		if (data.length() == 1 && !data.isNull(0)) {
			return (JSONObject) data.get(0);
		} else {
			throw new IllegalArgumentException("Invalid arguments specified!");
		}
	}
}
