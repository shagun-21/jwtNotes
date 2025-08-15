@Configuration
class MyConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder().
                username("DURGESH")
                .password(passwordEncoder().encode("DURGESH")).roles("ADMIN").
                build();
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}


my config is just a helper class that provides beans for password encoder and authentication manager and has userdetailservice implemented 
✅ So yes — this class is a helper/config class that sets up:

an in-memory user
password encoding
authentication manager
All beans are available for Spring Security to use.















@Component
public class JwtHelper {

    //requirement :
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    //    public static final long JWT_TOKEN_VALIDITY =  60;
    private String secret = "afafasfafafasfasfasfafacasdasfasxASFACASDFACASDFASFASFDAFASFASDAADSCSDFADCVSGCFVADXCcadwavfsfarvf";

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //generate token for user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


}




jwt helper is backbone which helps other file to validate and generate jwt token:
JwtHelper is essentially the utility/backbone for JWT operations. Its main responsibilities are:

Token Generation:

generateToken(UserDetails userDetails) → creates a JWT for a given user.

doGenerateToken(...) → actually builds the token with:

Claims (custom data, optional here)

Subject (username)

Issued at & Expiration date

Signature using HS512 + secret key

Token Parsing / Claims Extraction:

getUsernameFromToken(token) → extracts username from JWT.

getExpirationDateFromToken(token) → extracts expiry.

getClaimFromToken(...) → generic method to extract any claim from token.

Token Validation:

validateToken(token, userDetails) → checks if the token belongs to the user and is not expired.

Token Expiry Check:

isTokenExpired(token) → returns true if token is expired.

So yes — this class is used by your authentication and security filters/controllers to:

Generate JWTs when users log in.

Validate incoming JWTs for protected API calls.

Extract user info from JWTs to authenticate requests.










@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(OncePerRequestFilter.class);
    @Autowired
    private JwtHelper jwtHelper;


    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

//        try {
//            Thread.sleep(500);
//        } catch (InterruptedException e) {
//            throw new RuntimeException(e);
//        }
        //Authorization

        String requestHeader = request.getHeader("Authorization");
        //Bearer 2352345235sdfrsfgsdfsdf
        logger.info(" Header :  {}", requestHeader);
        String username = null;
        String token = null;
        if (requestHeader != null && requestHeader.startsWith("Bearer")) {
            //looking good
            token = requestHeader.substring(7);
            try {

                username = this.jwtHelper.getUsernameFromToken(token);

            } catch (IllegalArgumentException e) {
                logger.info("Illegal Argument while fetching the username !!");
                e.printStackTrace();
            } catch (ExpiredJwtException e) {
                logger.info("Given jwt token is expired !!");
                e.printStackTrace();
            } catch (MalformedJwtException e) {
                logger.info("Some changed has done in token !! Invalid Token");
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();

            }


        } else {
            logger.info("Invalid Header Value !! ");
        }


        //
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {


            //fetch user detail from username
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            Boolean validateToken = this.jwtHelper.validateToken(token, userDetails);
            if (validateToken) {

                //set the authentication
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);


            } else {
                logger.info("Validation fails !!");
            }


        }

        filterChain.doFilter(request, response);


    }
}



Exactly! ✅ This is a custom Spring Security filter that you would register in your security configuration. Let me break it down clearly:

What JwtAuthenticationFilter does:

Extends OncePerRequestFilter:

This ensures the filter runs once per HTTP request.

Perfect for JWT validation because you only want to check the token once per request.

Extracts JWT from the Authorization Header:

Looks for the header: Authorization: Bearer <token>

Removes "Bearer " prefix and gets the raw token.

Parses the Token:

Uses JwtHelper.getUsernameFromToken(token) to extract the username.

Handles exceptions: expired token, malformed token, illegal argument, etc.

Validates the Token:

Checks if the token is valid for the user (jwtHelper.validateToken(token, userDetails)).

Sets Authentication in Security Context:

If token is valid, it creates a UsernamePasswordAuthenticationToken and sets it in SecurityContextHolder.

This is how Spring Security knows the user is authenticated for the current request.

Passes Request Down the Filter Chain:

filterChain.doFilter(request, response) ensures the request continues to the next filter or endpoint.















@Configuration
public class SecurityConfig {


    @Autowired
    private JwtAuthenticationEntryPoint point;
    @Autowired
    private JwtAuthenticationFilter filter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(csrf -> csrf.disable())
                .authorizeRequests().
                requestMatchers("/test").authenticated().requestMatchers("/auth/login").permitAll()
                .anyRequest()
                .authenticated()
                .and().exceptionHandling(ex -> ex.authenticationEntryPoint(point))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


}







✅ In short:

Defines which endpoints require authentication.
Handles unauthorized access.
Configures stateless JWT authentication.
Adds your custom JWT filter into the Spring Security filter chain.


















@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager manager;


    @Autowired
    private JwtHelper helper;

    private Logger logger = LoggerFactory.getLogger(AuthController.class);


    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) {

        this.doAuthenticate(request.getEmail(), request.getPassword());


        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        String token = this.helper.generateToken(userDetails);

        JwtResponse response = JwtResponse.builder()
                .jwtToken(token)
                .username(userDetails.getUsername()).build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    private void doAuthenticate(String email, String password) {

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, password);
        try {
            manager.authenticate(authentication);


        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(" Invalid Username or Password  !!");
        }

    }

    @ExceptionHandler(BadCredentialsException.class)
    public String exceptionHandler() {
        return "Credentials Invalid !!";
    }

}










Flow in AuthController

Receives Login Request

@PostMapping("/login")
public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request)


Accepts JSON like { "email": "DURGESH", "password": "DURGESH" }.

Authenticates Credentials

this.doAuthenticate(request.getEmail(), request.getPassword());


Creates a UsernamePasswordAuthenticationToken.

Uses AuthenticationManager (from MyConfig) to check credentials against the in-memory user.

Throws BadCredentialsException if invalid.

Generates JWT

UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
String token = this.helper.generateToken(userDetails);


Loads user details from UserDetailsService (in-memory user from MyConfig).

Uses JwtHelper to generate a JWT token.

Returns JWT in Response

JwtResponse response = JwtResponse.builder()
        .jwtToken(token)
        .username(userDetails.getUsername()).build();


Sends JWT + username back to client.

Client will use this JWT in Authorization: Bearer <token> header for protected endpoints.

Exception Handling

@ExceptionHandler(BadCredentialsException.class)
public String exceptionHandler() { ... }


Returns a friendly message if login fails.

✅ How it uses everything we created:
Component	Usage
MyConfig	Provides UserDetailsService, PasswordEncoder, and AuthenticationManager
JwtHelper	Generates JWT token for authenticated user
JwtAuthenticationFilter	Not directly used here, but will validate this token on subsequent requests
SecurityConfig	Secures /auth/login as public endpoint and protects other endpoints

💡 Summary:

AuthController is the entry point for login.

MyConfig checks credentials.

JwtHelper generates JWT.

JwtAuthenticationFilter will later verify this token for secured requests.




