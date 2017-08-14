// OAuth2
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpResponseException;

// API scopes
import com.google.api.services.siteVerification.SiteVerificationScopes;
import com.google.api.services.admin.directory.DirectoryScopes;
import com.google.api.services.reseller.ResellerScopes;

// Reseller API
import com.google.api.services.reseller.Reseller;
import com.google.api.services.reseller.model.Customer;
import com.google.api.services.reseller.model.Address;
import com.google.api.services.reseller.model.RenewalSettings;
import com.google.api.services.reseller.model.Seats;
import com.google.api.services.reseller.model.Subscription;
import com.google.api.services.reseller.model.Subscription.Plan;
import com.google.api.services.reseller.model.Subscriptions;

// Directory API
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.model.User;
import com.google.api.services.admin.directory.model.UserName;
import com.google.api.services.admin.directory.model.UserMakeAdmin;

// Site Verification API
import com.google.api.services.siteVerification.SiteVerification;
import com.google.api.services.siteVerification.model.SiteVerificationWebResourceGettokenRequest;
import com.google.api.services.siteVerification.model.SiteVerificationWebResourceGettokenRequest.Site;
import com.google.api.services.siteVerification.model.SiteVerificationWebResourceGettokenResponse;
import com.google.api.services.siteVerification.model.SiteVerificationWebResourceResource;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GSuiteCreator {
    private static final String APP_NAME = "ResellerCodelab";
    private static final String SITE_TYPE = "INET_DOMAIN";
    private static final String VERIFICATION_METHOD = "DNS_TXT";
    private static final List<String> SCOPES = Arrays.asList(
        ResellerScopes.APPS_ORDER,
        SiteVerificationScopes.SITEVERIFICATION,
        DirectoryScopes.ADMIN_DIRECTORY_USER
    );

    /* REPLACE THESE WITH YOUR OWN */
    private static final String JSON_PRIVATE_KEY_FILE = "jsonprivatekey.json";
    private static final String RESELLER_ADMIN = "admin@resellerdomain.com";
    

    private GoogleCredential cred;
    private Reseller reseller_service;
    private Directory directory_service;
    private SiteVerification verification_service;

    public GSuiteCreator() throws IOException, GeneralSecurityException {
        this.cred = getJsonCredentials();
        // Create Reseller Service Object
        this.reseller_service = new Reseller.Builder(
            this.cred.getTransport(),
            this.cred.getJsonFactory(),
            this.cred).setApplicationName(APP_NAME).build();
        // Create Directory Service Object
        this.directory_service = new Directory.Builder(
            this.cred.getTransport(),
            this.cred.getJsonFactory(),
            this.cred).setApplicationName(APP_NAME).build();
        // Create Site Verification Service Object
        this.verification_service = new SiteVerification.Builder(
            this.cred.getTransport(),
            this.cred.getJsonFactory(),
            this.cred).setApplicationName(APP_NAME).build();
    }
    
    public static GoogleCredential getJsonCredentials()
        throws IOException, FileNotFoundException, GeneralSecurityException {
      GoogleCredential jsonCredentials = 
          GoogleCredential.fromStream(new FileInputStream(JSON_PRIVATE_KEY_FILE));
      return new GoogleCredential.Builder()
        .setTransport(GoogleNetHttpTransport.newTrustedTransport())
        .setJsonFactory(JacksonFactory.getDefaultInstance())
        .setServiceAccountScopes(SCOPES)
        .setServiceAccountUser(RESELLER_ADMIN)
        .setServiceAccountPrivateKey(jsonCredentials.getServiceAccountPrivateKey())
        .setServiceAccountId(jsonCredentials.getServiceAccountId())
        .build();
    }

    public Customer getCustomer(String customer_domain) throws IOException {
        return this.reseller_service.customers().get(customer_domain).execute();
    }

    public boolean hasCustomer(String customer_domain) throws IOException {
        boolean customer_exists = false;
        try {
            this.getCustomer(customer_domain);
            // no error thrown
            customer_exists = true;
        } catch (HttpResponseException e) {
            if (e.getStatusCode() == 404) {
                // no customer found
                customer_exists = false;
            } else throw e;
        }
        return customer_exists;
    }

    public void createCustomer(String customer_domain) throws IOException {
        Address address = new Address()
            .setContactName("Marty McFly")
            .setOrganizationName("Acme Corp")
            .setCountryCode("US")
            .setPostalCode("10009");

        Customer customer = new Customer()
            .setCustomerDomain(customer_domain)
            .setAlternateEmail("marty.mcfly@gmail.com")
            .setPostalAddress(address);

        if (!this.hasCustomer(customer_domain)) {
            this.reseller_service.customers().insert(customer).execute();
        } else {
            System.out.println("Customer already exists.");
        }
    }

    public void createUser(String user_email) throws IOException {
        UserName name = new UserName();
        name.setGivenName("Marty");
        name.setFamilyName("McFly");

        User user = new User();
        user.setPrimaryEmail(user_email);
        user.setPassword("TimeCircuit88");
        user.setName(name);

        this.directory_service.users().insert(user).execute();
    }

    public User getUser(String user_email) throws IOException {
        User u = this.directory_service.users().get(user_email).execute();
        return u;
    }

    public void setUserAdminStatus(String user_email, boolean is_admin) throws IOException {
        UserMakeAdmin admin = new UserMakeAdmin();
        admin.setStatus(is_admin);
        this.directory_service.users().makeAdmin(user_email, admin).execute();
    }

    public void createAdminUser(String user_email) throws IOException {
        this.createUser(user_email);
        this.setUserAdminStatus(user_email, true);
    }

    public void createSubscription(String customer_domain) throws IOException {
        Seats seats = new Seats().setNumberOfSeats(5);
        Plan plan = new Plan().setPlanName("ANNUAL_MONTHLY_PAY");        
        RenewalSettings renewalSettings = new RenewalSettings()
            .setRenewalType("RENEW_CURRENT_USERS_MONTHLY_PAY");
        
        Subscription subscription = new Subscription()
            .setCustomerId(customer_domain)
            .setSkuId("Google-Apps-For-Business")
            .setPlan(plan)
            .setSeats(seats)
            .setRenewalSettings(renewalSettings)
            .setPurchaseOrderId("blah123");
        
        this.reseller_service.subscriptions().insert(customer_domain, subscription).execute();
    }
    
    public Subscriptions listSubscriptions(String customer_id) throws IOException {
        Subscriptions subs = this.reseller_service.subscriptions().list()
            .setCustomerId(customer_id).execute();
        return subs;
    }
    
    public String getVerificationToken(String customer_domain) throws IOException {
        Site site = new Site().setType(SITE_TYPE).setIdentifier(customer_domain);
        SiteVerificationWebResourceGettokenRequest request = 
            new SiteVerificationWebResourceGettokenRequest()
            .setVerificationMethod(VERIFICATION_METHOD)
            .setSite(site);
        SiteVerificationWebResourceGettokenResponse response = 
            this.verification_service.webResource().getToken(request).execute();
        String token = response.getToken();
        return token;
    }
    
    public SiteVerificationWebResourceResource verifyDomain(String customer_domain,
        String admin_user) throws IOException {
        SiteVerificationWebResourceResource.Site site = 
            new SiteVerificationWebResourceResource.Site()
            .setIdentifier(customer_domain)
            .setType(SITE_TYPE);

        List<String> owners = new ArrayList<String>();
        owners.add(admin_user);

        SiteVerificationWebResourceResource resource = new SiteVerificationWebResourceResource()
            .setSite(site)
            .setOwners(owners);
        SiteVerificationWebResourceResource resp = this.verification_service.webResource()
            .insert(VERIFICATION_METHOD, resource)
            .execute();
        return resp;
    }
    
    public SiteVerificationWebResourceResource getDomainOwnership(String customer_domain)
        throws IOException {
        String id = "dns://" + customer_domain;
        SiteVerificationWebResourceResource resp = this.verification_service.webResource().get(id).execute();
        return resp;
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
      /* REPLACE THESE WITH YOUR OWN */
        String domain = "acme.com";
        String admin_user = "marty.mcfly@" + domain;

        // Step 1: Set up authentication and credentials
        GSuiteCreator gSuiteCreator = new GSuiteCreator();

        // Step 2: Begin domain verification process (Finished in Step 6)
        // Step 2.1: Retrieve a site verification token
        String token = gSuiteCreator.getVerificationToken(domain);
        System.out.println(token);
        // Step 2.2: Place site verification token in DNS records or site
        // See https://devsite.googleplex.com/site-verification/v1/getting_started#tokens
        
        // Step 3: Create a customer with the Reseller API
        gSuiteCreator.createCustomer(domain);
        Customer c = gSuiteCreator.getCustomer(domain);
        System.out.println(c);

        // Step 4: Create the first admin user with the Directory API
        gSuiteCreator.createAdminUser(admin_user);
        User u = gSuiteCreator.getUser(admin_user);
        System.out.println(u);

        // Step 5: Create a G Suite subscription for a customer
        gSuiteCreator.createSubscription(domain);
        Subscriptions s = gSuiteCreator.listSubscriptions(domain);
        System.out.println(s);

        // Step 6: Finish domain verification process
        gSuiteCreator.verifyDomain(domain, admin_user);
        SiteVerificationWebResourceResource r = gSuiteCreator.getDomainOwnership(domain);
        System.out.println(r);
    }
}


