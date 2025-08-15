# JWT Notes

---

## 1. `MyConfig`: Helper & Configuration Class

```java
@Configuration
class MyConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder()
            .username("DURGESH")
            .password(passwordEncoder().encode("DURGESH")).roles("ADMIN")
            .build();
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
```

> **Description:**
my config is just a helper class that provides beans for password encoder and authentication manager and has userdetailservice implemented
✅ So yes — this class is a helper/config class that sets up:
- an in-memory user
- password encoding
- authentication manager
- All beans are available for Spring Security to use.

---

## 2. `JwtHelper`: The Backbone for JWT Operations

```java
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
```

> **Description:**
jwt helper is backbone which helps other file to validate and generate jwt token:
JwtHelper is essentially the utility/backbone for JWT operations. Its main responsibilities are:
- **Token Generation:**
  - `generateToken(UserDetails userDetails)` → creates a JWT for a given user.
  - `doGenerateToken(...)` → actually builds the token with Claims, Subject, Issue/Expiry date, signature.
- **Token Parsing / Claims Extraction:**
  - `getUsernameFromToken(token)` → extracts username
  - `getExpirationDateFromToken(token)` → extracts expiry
  - `getClaimFromToken(...)` → generic method
- **Token Validation:**
  - `validateToken(token, userDetails)` → checks if the token belongs to the user and is not expired
- **Token Expiry Check:**
  - `isTokenExpired(token)` → true if token is expired
- Used by authentication and security filters/controllers to:
  - Generate JWTs when users log in
  - Validate incoming JWTs for protected API calls
  - Extract user info from JWTs to authenticate requests

---

## 3. `JwtAuthenticationFilter`: Custom Spring Security Filter

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(OncePerRequestFilter.class);
    @Autowired
    private JwtHelper jwtHelper;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Authorization
        String requestHeader = request.getHeader("Authorization");
        logger.info(" Header :  {}", requestHeader);
        String username = null;
        String token = null;
        if (requestHeader != null && requestHeader.startsWith("Bearer")) {
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

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            Boolean validateToken = this.jwtHelper.validateToken(token, userDetails);
            if (validateToken) {
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
```

> **Description:**
Exactly! ✅ This is a custom Spring Security filter that you would register in your security configuration.
**What JwtAuthenticationFilter does:**
- Extends `OncePerRequestFilter`: runs once per HTTP request
- Extracts JWT from `Authorization: Bearer <token>` header
- Parses and validates token via JwtHelper
- Handles exceptions (expired/malformed token, etc.)
- If valid, sets authentication into Spring Security context
- Passes request down the filter chain

---

## 4. `SecurityConfig`: Security Configuration

```java
@Configuration
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationEntryPoint point;
    @Autowired
    private JwtAuthenticationFilter filter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeRequests()
                .requestMatchers("/test").authenticated()
                .requestMatchers("/auth/login").permitAll()
                .anyRequest().authenticated()
                .and().exceptionHandling(ex -> ex.authenticationEntryPoint(point))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

> **Description:**
✅ In short:
- Defines which endpoints require authentication
- Handles unauthorized access
- Configures stateless JWT authentication
- Adds your custom JWT filter into the Spring Security filter chain

---

## 5. `AuthController`: REST Login Endpoint

```java
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
```

> **Flow in AuthController:**
- **Receives Login Request:**
  - `@PostMapping("/login")`
  - Accepts JSON like `{ "email": "DURGESH", "password": "DURGESH" }`
- **Authenticates Credentials:**
  - Uses `doAuthenticate` + `AuthenticationManager` (from MyConfig)
  - Throws BadCredentialsException if invalid
- **Generates JWT:**
  - Loads user details from UserDetailsService (in-memory user from MyConfig)
  - Uses JwtHelper to generate a JWT token
- **Returns JWT in Response:**
  - Sends JWT + username back to client
  - Client will use this JWT in `Authorization: Bearer <token>` header for protected endpoints
- **Exception Handling:**
  - Returns a friendly message if login fails

---

## 6. How Everything Works Together

| Component                | Usage                                                    |
|--------------------------|----------------------------------------------------------|
| **MyConfig**             | Provides UserDetailsService, PasswordEncoder, and AuthenticationManager |
| **JwtHelper**            | Generates JWT token for authenticated user               |
| **JwtAuthenticationFilter** | Validates this token on subsequent requests           |
| **SecurityConfig**       | Secures `/auth/login` as public endpoint, protects others|
| **AuthController**       | Entry point for login                                   |

---

> 💡 **Summary:**
- AuthController is the entry point for login
- MyConfig checks credentials
- JwtHelper generates JWT
- JwtAuthenticationFilter will later verify this token for secured requests
