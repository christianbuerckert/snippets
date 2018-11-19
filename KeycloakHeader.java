import java.util.Objects;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.ParseException;
import org.apache.http.message.BasicHeader;
import org.keycloak.RSATokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

/**
 * Pretty simple implementation of a self refreshing keycloak security header.
 *
 * @author cbuerckert
 */
public class KeycloakHeader implements Header {

    private int refreshBefore = 1;

    private final String realm;
    private final String authUrl;
    private final HttpEntity<MultiValueMap<String, String>> request;
    private final RestTemplate template = new RestTemplate();

    private AccessToken currentToken;
    private BasicHeader header;

    public KeycloakHeader(String authUrl, String realm, String clientId, String username, String password) {
        MultiValueMap<String, String> valueMap = new LinkedMultiValueMap<>();
        valueMap.add("grant_type", "password");
        valueMap.add("client_id", clientId);
        valueMap.add("username", username);
        valueMap.add("password", password);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        this.authUrl = authUrl;
        this.realm = realm;
        this.request = new HttpEntity<>(valueMap, headers);
    }

    public KeycloakHeader(String authUrl, String realm, String clientId, String clientSecret) {
        MultiValueMap<String, String> valueMap = new LinkedMultiValueMap<>();
        valueMap.add("grant_type", "client_credentials");
        valueMap.add("client_id", clientId);
        valueMap.add("client_secret", clientSecret);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        this.authUrl = authUrl;
        this.realm = realm;
        this.request = new HttpEntity<>(valueMap, headers);
    }

    /**
     * Defines the seconds before expiration which will cause a refresh. Default
     * is 1s;
     *
     * @param refreshBefore
     */
    public void setRefreshBefore(int refreshBefore) {
        this.refreshBefore = refreshBefore;
    }

    private String requestToken() {
        String url = authUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        ResponseEntity<AccessTokenResponse> response = template.postForEntity(url, request, AccessTokenResponse.class);
        return Objects.requireNonNull(response.getBody(), "No token received").getToken();
    }

    protected Header getValidHeader() {
        try {
            if (header == null
                    || currentToken == null
                    || !currentToken.isActive(refreshBefore)) {
                String tokenString = requestToken();
                currentToken = RSATokenVerifier.create(tokenString).getToken();
                header = new BasicHeader("Authorization", "Bearer " + tokenString);
            }
            return header;
        } catch (VerificationException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public HeaderElement[] getElements() throws ParseException {
        return getValidHeader().getElements();
    }

    @Override
    public String getName() {
        return getValidHeader().getName();
    }

    @Override
    public String getValue() {
        return getValidHeader().getValue();
    }

    @Override
    public String toString() {
        return getValidHeader().toString();
    }

}
