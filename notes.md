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
