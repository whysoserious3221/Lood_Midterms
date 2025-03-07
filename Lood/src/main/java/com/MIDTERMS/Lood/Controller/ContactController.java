package com.MIDTERMS.Lood.Controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import com.MIDTERMS.Lood.Service.ContactService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/")
public class ContactController {

    @Autowired
    private ContactService contactService;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;

    private String retrieveAccessToken() {
        OAuth2AuthenticationToken authentication =
                (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());

        if (client == null || client.getAccessToken() == null ||
                client.getAccessToken().getExpiresAt().isBefore(Instant.now())) {
            client = authorizedClientManager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId(
                            authentication.getAuthorizedClientRegistrationId())
                    .principal(authentication)
                    .build());
        }

        if (client == null || client.getAccessToken() == null) {
            throw new RuntimeException("Failed to retrieve access token.");
        }

        return client.getAccessToken().getTokenValue();
    }

    private Credential createCredential() {
        return new Credential(BearerToken.authorizationHeaderAccessMethod())
                .setAccessToken(retrieveAccessToken());
    }

    @GetMapping("login.html")
    public String login() {
        return "login";
    }

    @GetMapping("display.html")
    public String display(Model model) throws GeneralSecurityException, IOException {
        Credential credential = createCredential();
        String jsonResponse = contactService.getAllContacts(credential);

        List<Map<String, Object>> contacts = new ObjectMapper().readValue(
                jsonResponse, new TypeReference<>() {});

        model.addAttribute("contacts", contacts);
        return "display";
    }

    @PostMapping("create-contact")
    public String createContact(String name, String email, String phone) throws GeneralSecurityException, IOException {
        contactService.createContact(createCredential(), name, email, phone);
        return "redirect:/display.html";
    }

    @PostMapping("update-contact")
    public String updateContact(String resourceName, String name, String email, String phone)
            throws GeneralSecurityException, IOException {
        contactService.updateContact(createCredential(), resourceName, name, email, phone);
        return "redirect:/display.html";
    }

    @PostMapping("delete-contact")
    public String deleteContact(String resourceName) throws GeneralSecurityException, IOException {
        contactService.deleteContact(createCredential(), resourceName);
        return "redirect:/display.html";
    }
}