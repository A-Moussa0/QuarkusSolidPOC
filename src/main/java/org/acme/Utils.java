package org.acme;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.config.ConfigProvider;

import javax.ws.rs.core.NewCookie;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

@Slf4j
public class Utils {

    public static List<NewCookie> getAuthCookies(JsonNode keycloakResponse) {
        if (keycloakResponse == null) {
            return Collections.emptyList();
        }

        List<String> fields = new ArrayList<>();
        for (Iterator<String> it = keycloakResponse.fieldNames(); it.hasNext(); ) {
            fields.add(it.next());
        }
        log.info("Fields from keycloak: {}", fields);

        if (!keycloakResponse.has("access_token")) {
            log.warn("Failed to get token from keycloak (token not in data)");
            //TODO:: handle
            throw new IllegalStateException("Token not in data");
        }

        String jwt = keycloakResponse.get("access_token").asText();
        int jwt_expires_in = keycloakResponse.get("expires_in").asInt();
        String refresh_token = null;
        int refreshExpiresIn = jwt_expires_in;
        if (keycloakResponse.has("refresh_token")) {
            refresh_token = keycloakResponse.get("refresh_token").asText();
            refreshExpiresIn = keycloakResponse.get("refresh_expires_in").asInt();
        }

        log.debug("JWT got from external auth: {}", jwt);

        List<NewCookie> newCookies = new ArrayList<>();
        log.debug("access property of cookie name {}", ConfigProvider.getConfig().getValue("mp.jwt.token.cookie", String.class));
        if (refresh_token != null) {
            newCookies.add(
                    getNewCookie(
                            ConfigProvider.getConfig().getValue("mp.jwt.token.cookie", String.class) + "_refresh",
                            refresh_token,
                            "JWT refresh token.",
                            refreshExpiresIn
                    )
            );
        }

        return newCookies;
    }

    public static NewCookie getNewCookie(
            String cookieName,
            String value,
            String comment,
            int maxAgeSecs
    ) {
        return new NewCookie(
                cookieName,
                value,
                "/",
                ConfigProvider.getConfig().getValue("runningInfo.hostname", String.class),
                comment,
                maxAgeSecs,
                false,
                true

        );
    }
}
