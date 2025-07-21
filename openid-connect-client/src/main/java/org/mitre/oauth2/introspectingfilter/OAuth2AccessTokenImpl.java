/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.mitre.oauth2.introspectingfilter;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

import com.google.gson.JsonObject;

public class OAuth2AccessTokenImpl extends OAuth2AccessToken {

	private JsonObject introspectionResponse;

	public OAuth2AccessTokenImpl(JsonObject introspectionResponse, String tokenValue) {
		super(TokenType.BEARER,
			tokenValue,
			extractIssuedAt(introspectionResponse),
			extractExpiresAt(introspectionResponse),
			extractScopes(introspectionResponse));

		this.setIntrospectionResponse(introspectionResponse);
	}

	private static Instant extractIssuedAt(JsonObject introspectionResponse) {
		if (introspectionResponse.has("iat") && !introspectionResponse.get("iat").isJsonNull()) {
			return Instant.ofEpochSecond(introspectionResponse.get("iat").getAsLong());
		}
		return null;
	}

	private static Instant extractExpiresAt(JsonObject introspectionResponse) {
		if (introspectionResponse.has("exp") && !introspectionResponse.get("exp").isJsonNull()) {
			return Instant.ofEpochSecond(introspectionResponse.get("exp").getAsLong());
		}
		return null;
	}

	private static Set<String> extractScopes(JsonObject introspectionResponse) {
		if (introspectionResponse.has("scope") && !introspectionResponse.get("scope").isJsonNull()) {
			String scopeString = introspectionResponse.get("scope").getAsString();
			if (scopeString != null && !scopeString.trim().isEmpty()) {
				return Arrays.stream(scopeString.split(" "))
					.collect(Collectors.toSet());
			}
		}
		return new HashSet<>(); // Return empty set if no scopes
	}

	@Override
	public TokenType getTokenType() {
		return TokenType.BEARER;
	}

	/**
	 * @return the token
	 */
	public JsonObject getIntrospectionResponse() {
		return introspectionResponse;
	}

	/**
	 * @param token the token to set
	 */
	public void setIntrospectionResponse(JsonObject token) {
		this.introspectionResponse = token;
	}

}
