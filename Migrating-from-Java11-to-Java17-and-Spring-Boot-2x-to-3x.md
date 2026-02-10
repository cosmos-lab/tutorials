# Complete Migration Guide: Java 11 → 17 & Spring Boot 2.x → 3.x

Upgrading from Java 11 to 17 and Spring Boot 2.x to 3.x is a major architectural shift that requires careful planning and execution. This comprehensive guide provides a structured, step-by-step approach to manage the entire migration process safely and efficiently.

---

## Table of Contents
1. [Phase 0: Risk Assessment & Planning](#phase-0-risk-assessment--planning)
2. [Phase 1: Pre-Migration Preparation](#phase-1-pre-migration-preparation)
3. [Phase 2: Java 11 → Java 17 Migration](#phase-2-java-11--java-17-migration)
4. [Phase 3: The "Big Rename" (Javax → Jakarta)](#phase-3-the-big-rename-javax--jakarta)
5. [Phase 4: Spring Boot 3 Framework-Specific Changes](#phase-4-spring-boot-3-framework-specific-changes)
6. [Phase 5: Infrastructure & Testing](#phase-5-infrastructure--testing)
7. [Phase 6: Security Hardening](#phase-6-security-hardening)
8. [Phase 7: Performance Optimization](#phase-7-performance-optimization)
9. [Phase 8: Documentation & Knowledge Transfer](#phase-8-documentation--knowledge-transfer)
10. [Phase 9: Post-Migration Validation](#phase-9-post-migration-validation)
11. [Rollout Strategy](#phase-10-rollout-strategy)
12. [Common Pitfalls & Solutions](#common-pitfalls--solutions)
13. [Complete Checklist](#complete-migration-checklist)
14. [Tools & Resources](#tools--resources)

---

## Phase 0: Risk Assessment & Planning

Before beginning the migration, establish a solid foundation with proper planning.

### 0.1 Project Planning
- [ ] **Create a migration timeline** (typically 4-8 weeks for medium-sized applications)
- [ ] **Identify business-critical periods** to avoid (end of quarter, peak seasons, major releases)
- [ ] **Establish a rollback window** (determine acceptable downtime tolerance)
- [ ] **Document current system metrics** (baseline performance, error rates, response times)
- [ ] **Get stakeholder buy-in** (developers, DevOps, QA, management, business teams)

### 0.2 Team Preparation
- [ ] Assign a migration lead
- [ ] Form a cross-functional team (backend, frontend, DevOps, QA)
- [ ] Schedule knowledge sharing sessions
- [ ] Set up communication channels for migration-specific issues

### 0.3 Environment Preparation
- [ ] Ensure development, staging, and production environments are available
- [ ] Set up separate migration branch in version control
- [ ] Create backup strategy for databases and configuration

---

## Phase 1: Pre-Migration Preparation (The Safety Net)

Before jumping to Boot 3.x, stabilize your current environment. This is the most critical phase.

### 1.1 Upgrade to Spring Boot 2.7.x

**Why**: Spring Boot 2.7 is the bridge release with deprecation warnings that become errors in 3.0.

**Action**: Update to the latest 2.7.x version (2.7.18 as of early 2025)

**Maven (`pom.xml`)**:
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
</parent>
```

**Gradle (`build.gradle`)**:
```gradle
plugins {
    id 'org.springframework.boot' version '2.7.18'
}
```

**Verification**: 
- Run your application
- Monitor logs for deprecation warnings
- Document all warnings for later fixes

### 1.2 Audit Dependencies

```bash
# Maven
mvn dependency:tree > dependencies.txt

# Gradle
gradle dependencies > dependencies.txt
```

Review all third-party libraries for Jakarta EE compatibility:
- Check if libraries have versions supporting Spring Boot 3.x
- Verify compatibility with Java 17
- Look for known migration issues

**Common problematic dependencies**:
- Older versions of Hibernate Validator
- Legacy Apache libraries (commons-lang, commons-collections)
- Custom servlet filters or listeners
- XML processing libraries
- Older versions of Jackson
- Legacy testing frameworks

**Tools for dependency analysis**:
```bash
# Check for dependency updates
mvn versions:display-dependency-updates

# Analyze dependencies
mvn dependency:analyze

# Find unused dependencies
mvn dependency:analyze -DignoreNonCompile
```

### 1.3 Fix All Deprecations

- Enable deprecation warnings in your IDE
- Address all `@Deprecated` usage in Spring Boot 2.7
- Focus on:
  - Configuration properties
  - Security configurations (WebSecurityConfigurerAdapter)
  - Actuator endpoints
  - WebMVC/WebFlux configurations
  - Data access patterns
  - Bean definitions

### 1.4 Test Coverage

- [ ] Ensure test coverage is >70% before migration
- [ ] Document any areas with poor coverage for manual testing later
- [ ] Create integration tests for critical business flows
- [ ] Set up performance benchmarks for comparison

---

## Phase 2: Java 11 → Java 17 Migration

Java 17 is the **minimum** requirement for Spring Boot 3.0 (LTS until September 2029).

### 2.1 Update Build Configuration

**Maven (`pom.xml`)**:
```xml
<properties>
    <java.version>17</java.version>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
</properties>
```

**Gradle (`build.gradle`)**:
```gradle
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
```

### 2.2 Update Development Environment

- **IDE**: 
  - IntelliJ IDEA 2021.2.1+ 
  - Eclipse 2021-09+
  - VS Code with Java Extension Pack
- **JDK**: Install JDK 17
  - Eclipse Temurin (recommended)
  - Amazon Corretto
  - Oracle JDK
  - Microsoft OpenJDK
- **Build Tools**:
  - Maven 3.8.1+
  - Gradle 7.5+

### 2.3 Update CI/CD Pipeline

**GitHub Actions**:
```yaml
name: Java CI

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up JDK 17
      uses: actions/setup-java@v3
      with:
        java-version: '17'
        distribution: 'temurin'
    - name: Build with Maven
      run: mvn clean verify
```

**Jenkins (Declarative Pipeline)**:
```groovy
pipeline {
    agent {
        docker {
            image 'eclipse-temurin:17-jdk'
        }
    }
    stages {
        stage('Build') {
            steps {
                sh 'mvn clean verify'
            }
        }
    }
}
```

**GitLab CI**:
```yaml
image: eclipse-temurin:17-jdk

build:
  stage: build
  script:
    - ./mvnw clean verify
```

### 2.4 Address Strong Encapsulation (JEP 403)

Java 17 restricts access to internal APIs. If you see `IllegalAccessException`:

**Quick fix (temporary)**:
```bash
# Add JVM flags for legacy libraries
--add-opens java.base/java.lang=ALL-UNNAMED
--add-opens java.base/java.util=ALL-UNNAMED
--add-opens java.base/java.nio=ALL-UNNAMED
```

**In Maven**:
```xml
<plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <configuration>
        <jvmArguments>
            --add-opens java.base/java.lang=ALL-UNNAMED
        </jvmArguments>
    </configuration>
</plugin>
```

**Better approach**: Update libraries to versions that don't rely on internal APIs.

### 2.5 Leverage Java 17 Features

#### Records (Replace DTOs)
```java
// Before
public class UserDTO {
    private String name;
    private String email;
    private int age;
    
    // Constructor, getters, setters, equals, hashCode, toString
}

// After
public record UserDTO(String name, String email, int age) {
    // Compact constructor for validation
    public UserDTO {
        if (age < 0) {
            throw new IllegalArgumentException("Age cannot be negative");
        }
    }
}
```

#### Text Blocks (Multiline Strings)
```java
// Before
String sql = "SELECT id, name, email\n" +
             "FROM users\n" +
             "WHERE active = true\n" +
             "ORDER BY name";

// After
String sql = """
    SELECT id, name, email
    FROM users
    WHERE active = true
    ORDER BY name
    """;

// HTML templates
String html = """
    <html>
        <body>
            <h1>Welcome %s</h1>
        </body>
    </html>
    """.formatted(userName);
```

#### Pattern Matching for instanceof
```java
// Before
if (obj instanceof String) {
    String s = (String) obj;
    System.out.println(s.toUpperCase());
}

// After
if (obj instanceof String s) {
    System.out.println(s.toUpperCase());
}

// Complex example
public double getPerimeter(Shape shape) {
    if (shape instanceof Rectangle r) {
        return 2 * r.length() + 2 * r.width();
    } else if (shape instanceof Circle c) {
        return 2 * c.radius() * Math.PI;
    }
    throw new IllegalArgumentException("Unknown shape");
}
```

#### Switch Expressions
```java
// Before
String result;
switch (day) {
    case MONDAY:
    case FRIDAY:
        result = "Working";
        break;
    case SATURDAY:
    case SUNDAY:
        result = "Weekend";
        break;
    default:
        result = "Other";
}

// After
String result = switch (day) {
    case MONDAY, FRIDAY -> "Working";
    case SATURDAY, SUNDAY -> "Weekend";
    default -> "Other";
};
```

#### Sealed Classes (Java 17)
```java
public sealed interface Shape
    permits Circle, Rectangle, Triangle {
    double area();
}

public final class Circle implements Shape {
    private final double radius;
    
    public Circle(double radius) {
        this.radius = radius;
    }
    
    @Override
    public double area() {
        return Math.PI * radius * radius;
    }
}
```

### 2.6 Remove Deprecated Java APIs

- [ ] `java.security.acl` (removed in Java 17)
- [ ] Nashorn JavaScript engine (removed in Java 15)
- [ ] RMI Activation (removed in Java 17)
- [ ] Pack200 tools (removed in Java 14)
- [ ] Applet API (removed in Java 17)

### 2.7 Garbage Collection Changes

```bash
# Java 11 default: G1GC
# Java 17 default: Still G1GC, but with improvements

# Review existing GC flags
-XX:+UseG1GC
-XX:MaxGCPauseMillis=200
-XX:G1HeapRegionSize=16m

# Consider new GC options for low-latency requirements
# ZGC (production-ready in Java 17)
-XX:+UseZGC
-XX:ZCollectionInterval=5

# Shenandoah GC
-XX:+UseShenandoahGC
```

**Obsolete JVM flags in Java 17**:
```bash
# These flags no longer work:
-XX:+AggressiveOpts (removed)
-XX:+UseConcMarkSweepGC (removed in Java 14)
```

### 2.8 Remove SecurityManager Usage

SecurityManager is deprecated in Java 17 and will be removed in future versions.

```java
// Remove code like this:
System.setSecurityManager(new SecurityManager());

// Replace with alternative security mechanisms:
// - Application-level security
// - Container security
// - OS-level security
```

---

## Phase 3: The "Big Rename" (Javax → Jakarta)

Spring Boot 3 uses Jakarta EE 9+, requiring namespace changes for almost all enterprise APIs.

### 3.1 Automated Migration with OpenRewrite

OpenRewrite is the recommended tool for automated migration.

**Maven Setup**:
```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.openrewrite.maven</groupId>
            <artifactId>rewrite-maven-plugin</artifactId>
            <version>5.3.0</version>
            <configuration>
                <activeRecipes>
                    <recipe>org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_0</recipe>
                </activeRecipes>
            </configuration>
            <dependencies>
                <dependency>
                    <groupId>org.openrewrite.recipe</groupId>
                    <artifactId>rewrite-spring</artifactId>
                    <version>5.0.5</version>
                </dependency>
            </dependencies>
        </plugin>
    </plugins>
</build>
```

Run migration:
```bash
mvn rewrite:run
```

**Gradle Setup**:
```gradle
plugins {
    id 'org.openrewrite.rewrite' version '6.1.0'
}

rewrite {
    activeRecipe('org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_0')
}

dependencies {
    rewrite('org.openrewrite.recipe:rewrite-spring:5.0.5')
}
```

Run migration:
```bash
gradle rewriteRun
```

### 3.2 Manual Namespace Changes

Replace all `javax.*` imports with `jakarta.*`:

| Old (javax) | New (jakarta) | Common Use Cases |
|-------------|---------------|------------------|
| `javax.persistence.*` | `jakarta.persistence.*` | JPA entities, @Entity, @Table, @Column |
| `javax.servlet.*` | `jakarta.servlet.*` | Servlets, filters, listeners |
| `javax.validation.*` | `jakarta.validation.*` | @Valid, @NotNull, @Size |
| `javax.transaction.*` | `jakarta.transaction.*` | @Transactional |
| `javax.annotation.*` | `jakarta.annotation.*` | @PostConstruct, @PreDestroy |
| `javax.inject.*` | `jakarta.inject.*` | @Inject, @Named |
| `javax.ws.rs.*` | `jakarta.ws.rs.*` | JAX-RS (if using) |
| `javax.xml.bind.*` | `jakarta.xml.bind.*` | JAXB |
| `javax.jms.*` | `jakarta.jms.*` | JMS messaging |
| `javax.mail.*` | `jakarta.mail.*` | Email |

### 3.3 IDE-Based Migration

**IntelliJ IDEA**:
1. Right-click on project → **Refactor** → **Migrate Packages and Classes**
2. Select **"Java EE to Jakarta EE"**
3. Review the migration preview
4. Apply changes
5. Verify with "Find in Path" for any remaining `javax.*` imports

**Eclipse**:
1. Right-click on project → **Configure** → **Migrate to Jakarta EE**
2. Follow the migration wizard
3. Review and apply changes

**VS Code**:
- Use find and replace with regex
- Extension: "Spring Boot Tools" has migration support

### 3.4 Update Dependency Versions for Jakarta

```xml
<!-- Hibernate Validator -->
<dependency>
    <groupId>org.hibernate.validator</groupId>
    <artifactId>hibernate-validator</artifactId>
    <version>8.0.0.Final</version>
</dependency>

<!-- Jakarta Servlet API -->
<dependency>
    <groupId>jakarta.servlet</groupId>
    <artifactId>jakarta.servlet-api</artifactId>
    <version>6.0.0</version>
    <scope>provided</scope>
</dependency>

<!-- Jakarta Persistence API -->
<dependency>
    <groupId>jakarta.persistence</groupId>
    <artifactId>jakarta.persistence-api</artifactId>
    <version>3.1.0</version>
</dependency>

<!-- Jakarta Validation API -->
<dependency>
    <groupId>jakarta.validation</groupId>
    <artifactId>jakarta.validation-api</artifactId>
    <version>3.0.2</version>
</dependency>

<!-- Jakarta Mail -->
<dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>jakarta.mail</artifactId>
    <version>2.0.1</version>
</dependency>
```

### 3.5 Third-Party Library Updates

#### Essential Library Updates

```xml
<!-- Lombok: Required for Java 17 + Jakarta -->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.18.30</version>
    <scope>provided</scope>
</dependency>

<!-- MapStruct: Required for Java 17 -->
<dependency>
    <groupId>org.mapstruct</groupId>
    <artifactId>mapstruct</artifactId>
    <version>1.5.5.Final</version>
</dependency>

<dependency>
    <groupId>org.mapstruct</groupId>
    <artifactId>mapstruct-processor</artifactId>
    <version>1.5.5.Final</version>
    <scope>provided</scope>
</dependency>

<!-- Apache Commons -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-lang3</artifactId>
    <version>3.14.0</version>
</dependency>

<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.4</version>
</dependency>

<!-- Jackson: Critical for Boot 3 -->
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.15.2</version>
</dependency>

<dependency>
    <groupId>com.fasterxml.jackson.datatype</groupId>
    <artifactId>jackson-datatype-jsr310</artifactId>
    <version>2.15.2</version>
</dependency>
```

#### Database Drivers

```xml
<!-- PostgreSQL -->
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <version>42.6.0</version>
</dependency>

<!-- MySQL -->
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
    <version>8.2.0</version>
</dependency>

<!-- Oracle -->
<dependency>
    <groupId>com.oracle.database.jdbc</groupId>
    <artifactId>ojdbc11</artifactId>
    <version>23.2.0.0</version>
</dependency>

<!-- SQL Server -->
<dependency>
    <groupId>com.microsoft.sqlserver</groupId>
    <artifactId>mssql-jdbc</artifactId>
    <version>12.4.1.jre11</version>
</dependency>

<!-- H2 (for testing) -->
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <version>2.2.224</version>
    <scope>test</scope>
</dependency>
```

#### Cloud SDK Updates

```xml
<!-- AWS SDK v2 (required for Boot 3) -->
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>software.amazon.awssdk</groupId>
            <artifactId>bom</artifactId>
            <version>2.20.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<!-- Google Cloud -->
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.google.cloud</groupId>
            <artifactId>libraries-bom</artifactId>
            <version>26.22.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<!-- Azure Spring Cloud -->
<dependency>
    <groupId>com.azure.spring</groupId>
    <artifactId>spring-cloud-azure-dependencies</artifactId>
    <version>5.5.0</version>
    <type>pom</type>
    <scope>import</scope>
</dependency>
```

---

## Phase 4: Spring Boot 3 Framework-Specific Changes

### 4.1 Update Spring Boot Version

**Maven**:
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.2</version>
</parent>
```

**Gradle**:
```gradle
plugins {
    id 'org.springframework.boot' version '3.2.2'
    id 'io.spring.dependency-management' version '1.1.4'
}
```

### 4.2 Configuration Properties Migration

Add the **properties migrator** dependency (temporary, for development only):
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-properties-migrator</artifactId>
    <scope>runtime</scope>
</dependency>
```

This will log warnings about deprecated properties at runtime and suggest replacements.

**Common property changes**:

```properties
# Redis
# Before (Boot 2.x)
spring.redis.host=localhost
spring.redis.port=6379

# After (Boot 3.x)
spring.data.redis.host=localhost
spring.data.redis.port=6379

# Elasticsearch
# Before
spring.data.elasticsearch.cluster-name=my-cluster
spring.data.elasticsearch.cluster-nodes=localhost:9300

# After
spring.elasticsearch.uris=http://localhost:9200

# Logging
# Before
logging.file=app.log

# After
logging.file.name=app.log

# JPA
# Before
spring.jpa.hibernate.use-new-id-generator-mappings=true

# After (removed - Hibernate 6 uses new generator by default)
# No longer needed

# Actuator
# Before
management.metrics.export.prometheus.enabled=true

# After (still the same, but verify)
management.prometheus.metrics.export.enabled=true
```

**Remove the properties migrator** after fixing all properties - don't deploy to production with it.

### 4.3 Spring Security 6 Migration

This is one of the most significant breaking changes.

#### 4.3.1 WebSecurityConfigurerAdapter is Removed

**Before (Boot 2.x)**:
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
            .and()
            .logout()
                .permitAll();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("{noop}password").roles("USER")
            .and()
            .withUser("admin").password("{noop}admin").roles("ADMIN");
    }
}
```

**After (Boot 3.x)**:
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .logout(logout -> logout
                .permitAll()
            );
        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("user")
            .password("{noop}password")
            .roles("USER")
            .build();
            
        UserDetails admin = User.builder()
            .username("admin")
            .password("{noop}admin")
            .roles("ADMIN")
            .build();
            
        return new InMemoryUserDetailsManager(user, admin);
    }
}
```

#### 4.3.2 Key Security API Changes

| Old API (Boot 2.x) | New API (Boot 3.x) |
|-------------------|-------------------|
| `authorizeRequests()` | `authorizeHttpRequests()` |
| `antMatchers()` | `requestMatchers()` |
| `mvcMatchers()` | `requestMatchers()` |
| `regexMatchers()` | `requestMatchers()` with regex |
| `and()` | Lambda DSL (chainable) |

#### 4.3.3 Method Security

```java
// Enable method security
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {
    // Configuration
}

// Usage (same as before)
@Service
public class UserService {
    
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long userId) {
        // ...
    }
    
    @PostAuthorize("returnObject.username == authentication.name")
    public User getUserDetails(Long userId) {
        // ...
    }
}
```

#### 4.3.4 OAuth2/JWT Configuration

```java
@Configuration
@EnableWebSecurity
public class OAuth2SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            );
        return http.build();
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("https://your-auth-server.com");
    }
}
```

#### 4.3.5 CORS Configuration

```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### 4.4 Hibernate 6 Changes

Spring Boot 3 uses Hibernate 6 by default, which has several breaking changes.

#### 4.4.1 Enum Handling

```java
@Entity
public class User {
    @Id
    private Long id;
    
    // Before (Hibernate 5): Stored as VARCHAR by default
    @Enumerated
    private Status status;
    
    // After (Hibernate 6): Stored as INTEGER by default
    // Explicitly specify for backward compatibility:
    @Enumerated(EnumType.STRING)
    private Status status;
}

public enum Status {
    ACTIVE, INACTIVE, PENDING
}
```

#### 4.4.2 Query Changes

**Stricter HQL/JPQL parsing**:
```java
// This may fail in Hibernate 6:
@Query("SELECT u FROM User u WHERE u.status = 'ACTIVE'")
List<User> findActiveUsers();

// Fix: Use proper enum comparison
@Query("SELECT u FROM User u WHERE u.status = :status")
List<User> findByStatus(@Param("status") Status status);
```

**JOIN FETCH changes**:
```java
// Hibernate 6 is stricter about duplicate fetches
@Query("SELECT DISTINCT u FROM User u " +
       "LEFT JOIN FETCH u.roles " +
       "LEFT JOIN FETCH u.permissions")
List<User> findAllWithRolesAndPermissions();
```

#### 4.4.3 Identifier Generation

```java
@Entity
public class Product {
    // Hibernate 6 uses improved UUID generation
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    // Or for auto-increment
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
}
```

#### 4.4.4 SqmPathSource Changes

If you have custom Hibernate types or criteria queries, review them carefully:

```java
// Custom criteria queries may need updates
CriteriaBuilder cb = entityManager.getCriteriaBuilder();
CriteriaQuery<User> query = cb.createQuery(User.class);
Root<User> root = query.from(User.class);

// Join syntax may need adjustments
Join<User, Role> roleJoin = root.join("roles", JoinType.LEFT);
```

### 4.5 Trailing Slash Matching

Spring MVC no longer matches trailing slashes by default.

```java
// This controller:
@RestController
@RequestMapping("/api")
public class UserController {
    
    @GetMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }
}

// Before Boot 3: Both /api/users and /api/users/ work
// After Boot 3: Only /api/users works; /api/users/ returns 404
```

**Option 1: Update clients** (recommended)

**Option 2: Restore old behavior**:
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.setUseTrailingSlashMatch(true);
    }
}
```

### 4.6 Spring Data Changes

#### 4.6.1 Repository Method Removals

```java
public interface UserRepository extends JpaRepository<User, Long> {
    
    // REMOVED in Spring Data 3.x
    // Optional<User> user = userRepository.findOne(id);
    
    // Use this instead:
    Optional<User> user = userRepository.findById(id);
    
    // REMOVED: findOne(Example)
    // Use findBy(Example) instead
    
    // REMOVED: count(Example)
    // Use exists(Example) instead
}
```

#### 4.6.2 Query Method Changes

```java
// More strict query derivation
public interface UserRepository extends JpaRepository<User, Long> {
    
    // This still works
    List<User> findByEmailAndStatus(String email, Status status);
    
    // But be careful with complex queries - may need @Query
    @Query("SELECT u FROM User u WHERE u.email = :email AND u.status = :status")
    List<User> findActiveUsersByEmail(@Param("email") String email, 
                                      @Param("status") Status status);
}
```

### 4.7 Actuator Changes

#### 4.7.1 Endpoint Exposure

```properties
# Health endpoint details require explicit configuration
management.endpoint.health.show-details=always
management.endpoint.health.show-components=always

# Expose specific endpoints
management.endpoints.web.exposure.include=health,info,metrics,prometheus

# Or expose all (not recommended for production)
management.endpoints.web.exposure.include=*
```

#### 4.7.2 Metrics Changes

```java
@Component
public class CustomMetrics {
    
    private final MeterRegistry meterRegistry;
    
    public CustomMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }
    
    public void recordUserLogin(String username) {
        meterRegistry.counter("user.login", "username", username).increment();
    }
    
    public void recordApiCall(String endpoint, long duration) {
        meterRegistry.timer("api.call", "endpoint", endpoint)
            .record(duration, TimeUnit.MILLISECONDS);
    }
}
```

### 4.8 Spring Cloud Compatibility

**CRITICAL**: Not all Spring Cloud projects support Boot 3 immediately.

Check compatibility matrix:
- **Spring Cloud 2022.0.0+** required for Boot 3.0
- **Spring Cloud 2023.0.0+** recommended for Boot 3.2

```xml
<properties>
    <spring-cloud.version>2023.0.0</spring-cloud.version>
</properties>

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>${spring-cloud.version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

**Common Spring Cloud modules**:
```xml
<!-- Config Client -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-config</artifactId>
</dependency>

<!-- Service Discovery (Eureka) -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
</dependency>

<!-- Circuit Breaker (Resilience4j) -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-circuitbreaker-resilience4j</artifactId>
</dependency>

<!-- API Gateway -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-gateway</artifactId>
</dependency>
```

### 4.9 Removed Auto-Configurations

- [ ] Review `spring.autoconfigure.exclude` configurations
- [ ] Check custom `@AutoConfiguration` classes
- [ ] **IMPORTANT**: `META-INF/spring.factories` has been replaced

**Migration for custom auto-configurations**:

**Before (Boot 2.x)**: `META-INF/spring.factories`
```properties
org.springframework.boot.autoconfigure.EnableAutoConfiguration=\
com.example.MyAutoConfiguration
```

**After (Boot 3.x)**: `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
```
com.example.MyAutoConfiguration
```

### 4.10 Logging Changes

```properties
# Enhanced logging configuration with ANSI colors
logging.pattern.console=%clr(%d{yyyy-MM-dd HH:mm:ss.SSS}){faint} %clr(${LOG_LEVEL_PATTERN:-%5p}) %clr(${PID:- }){magenta} %clr(---){faint} %clr([%15.15t]){faint} %clr(%-40.40logger{39}){cyan} %clr(:){faint} %m%n${LOG_EXCEPTION_CONVERSION_WORD:-%wEx}

# File logging
logging.file.name=logs/application.log
logging.file.max-size=10MB
logging.file.max-history=30

# Log levels
logging.level.root=INFO
logging.level.com.example=DEBUG
logging.level.org.springframework.web=DEBUG
logging.level.org.hibernate.SQL=DEBUG
logging.level.org.hibernate.type.descriptor.sql.BasicBinder=TRACE
```

### 4.11 HTTP Client Changes

**RestTemplate** is not deprecated, but **WebClient** is recommended for new code.

```java
// RestTemplate still works
@Configuration
public class RestTemplateConfig {
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

// WebClient (recommended for Boot 3)
@Configuration
public class WebClientConfig {
    
    @Bean
    public WebClient webClient() {
        return WebClient.builder()
            .baseUrl("https://api.example.com")
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
    }
}

// Usage
@Service
public class ExternalApiService {
    
    private final WebClient webClient;
    
    public ExternalApiService(WebClient webClient) {
        this.webClient = webClient;
    }
    
    public Mono<User> getUser(Long id) {
        return webClient.get()
            .uri("/users/{id}", id)
            .retrieve()
            .bodyToMono(User.class);
    }
    
    public Mono<User> createUser(User user) {
        return webClient.post()
            .uri("/users")
            .bodyValue(user)
            .retrieve()
            .bodyToMono(User.class);
    }
}
```

---

## Phase 5: Infrastructure & Testing

### 5.1 Update Docker Images

**Before**:
```dockerfile
FROM openjdk:11-jre-slim
COPY target/app.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**After**:
```dockerfile
FROM eclipse-temurin:17-jre-alpine
COPY target/app.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**Multi-stage build (recommended)**:
```dockerfile
# Build stage
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN ./mvnw clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

# Add non-root user for security
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**With JVM optimization**:
```dockerfile
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY target/app.jar app.jar

# JVM optimization flags
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:InitialRAMPercentage=50.0"

EXPOSE 8080
ENTRYPOINT java $JAVA_OPTS -jar app.jar
```

### 5.2 Database Migrations

#### 5.2.1 Flyway

Update to version 9.0+ (default in Boot 3.x):
```xml
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-core</artifactId>
    <version>9.22.0</version>
</dependency>

<!-- For specific database support -->
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-mysql</artifactId>
</dependency>
```

Configuration:
```properties
spring.flyway.enabled=true
spring.flyway.locations=classpath:db/migration
spring.flyway.baseline-on-migrate=true
spring.flyway.validate-on-migrate=true
```

#### 5.2.2 Liquibase

Update to version 4.20+:
```xml
<dependency>
    <groupId>org.liquibase</groupId>
    <artifactId>liquibase-core</artifactId>
    <version>4.24.0</version>
</dependency>
```

Configuration:
```properties
spring.liquibase.enabled=true
spring.liquibase.change-log=classpath:db/changelog/db.changelog-master.xml
spring.liquibase.drop-first=false
```

### 5.3 Observability with Micrometer Tracing

**Spring Cloud Sleuth is REMOVED**. Use Micrometer Observation API.

#### 5.3.1 Add Dependencies

```xml
<!-- Micrometer Tracing Bridge for Brave -->
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-tracing-bridge-brave</artifactId>
</dependency>

<!-- Zipkin Reporter -->
<dependency>
    <groupId>io.zipkin.reporter2</groupId>
    <artifactId>zipkin-reporter-brave</artifactId>
</dependency>

<!-- For Prometheus metrics -->
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-registry-prometheus</artifactId>
</dependency>

<!-- For distributed tracing context propagation -->
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-tracing</artifactId>
</dependency>
```

#### 5.3.2 Configuration

```properties
# Tracing configuration
management.tracing.sampling.probability=1.0
management.zipkin.tracing.endpoint=http://localhost:9411/api/v2/spans

# Metrics configuration
management.metrics.distribution.percentiles-histogram.http.server.requests=true
management.metrics.tags.application=${spring.application.name}

# Prometheus endpoint
management.endpoints.web.exposure.include=health,info,metrics,prometheus
management.prometheus.metrics.export.enabled=true
```

#### 5.3.3 Custom Observations

```java
@Service
public class UserService {
    
    private final ObservationRegistry observationRegistry;
    private final UserRepository userRepository;
    
    public UserService(ObservationRegistry observationRegistry, 
                      UserRepository userRepository) {
        this.observationRegistry = observationRegistry;
        this.userRepository = userRepository;
    }
    
    public User createUser(User user) {
        return Observation
            .createNotStarted("user.create", observationRegistry)
            .lowCardinalityKeyValue("username", user.getUsername())
            .observe(() -> {
                // Business logic
                User savedUser = userRepository.save(user);
                return savedUser;
            });
    }
}
```

### 5.4 Testing Strategy

#### 5.4.1 Update Test Dependencies

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>

<!-- JUnit 5 (Jupiter) - default in Boot 3 -->
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <scope>test</scope>
</dependency>

<!-- Mockito -->
<dependency>
    <groupId>org.mockito</groupId>
    <artifactId>mockito-core</artifactId>
    <scope>test</scope>
</dependency>

<!-- AssertJ -->
<dependency>
    <groupId>org.assertj</groupId>
    <artifactId>assertj-core</artifactId>
    <scope>test</scope>
</dependency>

<!-- TestContainers for integration tests -->
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>testcontainers</artifactId>
    <version>1.19.3</version>
    <scope>test</scope>
</dependency>

<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>postgresql</artifactId>
    <version>1.19.3</version>
    <scope>test</scope>
</dependency>
```

#### 5.4.2 Unit Tests

```java
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @InjectMocks
    private UserService userService;
    
    @Test
    void shouldCreateUser() {
        // Given
        User user = new User("john@example.com", "John Doe");
        when(userRepository.save(any(User.class))).thenReturn(user);
        
        // When
        User result = userService.createUser(user);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getEmail()).isEqualTo("john@example.com");
        verify(userRepository).save(user);
    }
}
```

#### 5.4.3 Integration Tests

```java
@SpringBootTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class UserRepositoryIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
        .withDatabaseName("testdb")
        .withUsername("test")
        .withPassword("test");
    
    @Autowired
    private UserRepository userRepository;
    
    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }
    
    @Test
    void shouldSaveAndRetrieveUser() {
        // Given
        User user = new User("john@example.com", "John Doe");
        
        // When
        User saved = userRepository.save(user);
        Optional<User> retrieved = userRepository.findById(saved.getId());
        
        // Then
        assertThat(retrieved).isPresent();
        assertThat(retrieved.get().getEmail()).isEqualTo("john@example.com");
    }
}
```

#### 5.4.4 REST API Tests

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class UserControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @MockBean
    private UserService userService;
    
    @Test
    void shouldCreateUser() throws Exception {
        // Given
        User user = new User("john@example.com", "John Doe");
        when(userService.createUser(any(User.class))).thenReturn(user);
        
        // When & Then
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.email").value("john@example.com"))
            .andExpect(jsonPath("$.name").value("John Doe"));
    }
}
```

#### 5.4.5 Security Tests

```java
@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void shouldDenyAccessToProtectedEndpointWithoutAuth() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void shouldAllowAccessToAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isOk());
    }
    
    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    void shouldDenyAccessToAdminEndpointForRegularUser() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isForbidden());
    }
}
```

#### 5.4.6 Focus Areas for Testing

1. **Serialization/Deserialization**: Jackson behavior may change
   - Test JSON mapping for all DTOs
   - Verify date/time handling
   - Check enum serialization

2. **Database Queries**: Hibernate 6 query parsing
   - Test all custom JPQL queries
   - Verify native queries
   - Check pagination and sorting

3. **Security**: Authorization rules with new Security DSL
   - Test all endpoints with different roles
   - Verify CORS configuration
   - Check JWT token validation

4. **REST APIs**: Response formats and status codes
   - Verify all HTTP methods
   - Check error handling
   - Validate request/response bodies

5. **Actuator Endpoints**: Health checks and metrics
   - Test health endpoint
   - Verify custom metrics
   - Check info endpoint

### 5.5 Performance Testing

```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:8080/api/users

# Using JMeter
# Create test plan with thread groups

# Using Gatling
mvn gatling:test
```

**Key metrics to monitor**:
- Application startup time (Boot 3 should be faster)
- Memory footprint (heap and non-heap)
- GC pause times
- API response times (p50, p95, p99)
- Throughput (requests per second)

---

## Phase 6: Security Hardening

### 6.1 Dependency Vulnerability Scanning

#### 6.1.1 OWASP Dependency Check

```xml
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.0</version>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
    </configuration>
</plugin>
```

Run scan:
```bash
mvn org.owasp:dependency-check-maven:check
```

#### 6.1.2 Snyk

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Test for vulnerabilities
snyk test

# Monitor project
snyk monitor
```

### 6.2 Security Best Practices

```properties
# Disable unnecessary features
spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.admin.SpringApplicationAdminJmxAutoConfiguration

# HTTPS enforcement
server.ssl.enabled=true
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=${SSL_PASSWORD}
server.ssl.key-store-type=PKCS12

# Security headers
server.error.include-message=never
server.error.include-binding-errors=never
server.error.include-stacktrace=never
server.error.include-exception=false
```

### 6.3 APM Tool Updates

Ensure APM agents are compatible with Java 17 and Spring Boot 3:

- [ ] **New Relic**: Agent 8.0+ for Java 17
- [ ] **Datadog**: Agent 1.0+ for Java 17  
- [ ] **Dynatrace**: OneAgent 1.239+ for Java 17
- [ ] **AppDynamics**: Agent 22.1+ for Java 17
- [ ] **Elastic APM**: Agent 1.36+ for Java 17

**Example: New Relic configuration**:
```yaml
# newrelic.yml
common: &default_settings
  license_key: '<%= ENV["NEW_RELIC_LICENSE_KEY"] %>'
  app_name: My Application
  
production:
  <<: *default_settings
  enable_auto_app_naming: false
```

---

## Phase 7: Performance Optimization

### 7.1 JVM Tuning for Java 17

```bash
# Recommended JVM flags for containerized Spring Boot 3 apps
JAVA_OPTS="
  -XX:+UseContainerSupport
  -XX:MaxRAMPercentage=75.0
  -XX:InitialRAMPercentage=50.0
  -XX:+UseG1GC
  -XX:MaxGCPauseMillis=200
  -XX:+ParallelRefProcEnabled
  -XX:+DisableExplicitGC
  -Djava.security.egd=file:/dev/./urandom
"
```

### 7.2 Class Data Sharing (CDS)

Improve startup time with Class Data Sharing:

```bash
# Step 1: Generate class list
java -Xshare:off -XX:DumpLoadedClassList=app.classlist -jar app.jar

# Step 2: Create CDS archive
java -Xshare:dump -XX:SharedClassListFile=app.classlist -XX:SharedArchiveFile=app.jsa -jar app.jar

# Step 3: Use CDS archive
java -Xshare:on -XX:SharedArchiveFile=app.jsa -jar app.jar
```

### 7.3 GraalVM Native Image (Advanced)

Spring Boot 3 supports **GraalVM Native Image** for ultra-fast startup and low memory footprint.

**Benefits**:
- Instant startup (<100ms)
- Lower memory footprint (up to 5x reduction)
- Smaller container images

**Trade-offs**:
- Longer build times
- Reflection and dynamic features require configuration
- Not all libraries are compatible

#### Setup

```xml
<plugin>
    <groupId>org.graalvm.buildtools</groupId>
    <artifactId>native-maven-plugin</artifactId>
    <version>0.9.28</version>
    <extensions>true</extensions>
    <executions>
        <execution>
            <id>build-native</id>
            <goals>
                <goal>compile-no-fork</goal>
            </goals>
            <phase>package</phase>
        </execution>
    </executions>
</plugin>
```

Build native image:
```bash
mvn -Pnative native:compile
```

**Dockerfile for native image**:
```dockerfile
FROM ghcr.io/graalvm/native-image:ol8-java17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN ./mvnw -Pnative native:compile

FROM gcr.io/distroless/base
COPY --from=build /app/target/app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
```

### 7.4 Startup Optimization

```properties
# Lazy initialization (faster startup, slower first request)
spring.main.lazy-initialization=true

# Reduce Actuator endpoints
management.endpoints.web.exposure.include=health,info

# Disable JMX
spring.jmx.enabled=false

# Faster bean initialization
spring.main.allow-bean-definition-overriding=false
```

### 7.5 Connection Pooling

```properties
# HikariCP (default in Boot 3)
spring.datasource.hikari.maximum-pool-size=10
spring.datasource.hikari.minimum-idle=5
spring.datasource.hikari.connection-timeout=30000
spring.datasource.hikari.idle-timeout=600000
spring.datasource.hikari.max-lifetime=1800000
spring.datasource.hikari.leak-detection-threshold=60000
```

---

## Phase 8: Documentation & Knowledge Transfer

### 8.1 Update Project Documentation

- [ ] **README.md**: Update with new Java/Spring Boot versions
  ```markdown
  # Project Name
  
  ## Prerequisites
  - Java 17
  - Spring Boot 3.2.2
  - Maven 3.8.1+ or Gradle 7.5+
  
  ## Build
  ```bash
  mvn clean package
  ```
  
  ## Run
  ```bash
  java -jar target/app.jar
  ```
  ```

- [ ] **Developer Setup Guide**: Update IDE and JDK setup instructions
- [ ] **Architecture Documentation**: Update diagrams and dependency graphs
- [ ] **API Documentation**: Regenerate OpenAPI/Swagger docs

### 8.2 Migration Documentation

Create a migration log documenting:
- Issues encountered and solutions
- Breaking changes affecting the application
- Configuration changes required
- Performance improvements observed

### 8.3 Team Training

- [ ] Conduct training sessions on:
  - Java 17 new features
  - Spring Security 6 Lambda DSL
  - Micrometer Observability
  - Hibernate 6 changes
  
- [ ] Create internal knowledge base articles
- [ ] Record demo sessions for future reference

### 8.4 Runbook Creation

Create operational runbooks for:
- Deployment procedures
- Rollback procedures
- Common troubleshooting scenarios
- Monitoring and alerting setup

---

## Phase 9: Post-Migration Validation

### 9.1 Production Health Checks (First 48-72 Hours)

**Critical metrics to monitor**:

```bash
# Application startup time
journalctl -u myapp.service | grep "Started Application"

# Memory usage
jcmd <PID> VM.native_memory summary

# GC performance
jstat -gc <PID> 1000

# Thread count
jstack <PID> | grep "^Thread" | wc -l
```

**Checklist**:
- [ ] Monitor error rates (compare to baseline)
- [ ] Check for memory leaks (heap dumps)
- [ ] Review GC pause times
- [ ] Validate distributed tracing
- [ ] Check database connection pool health
- [ ] Verify scheduled jobs run correctly
- [ ] Test circuit breakers (if using Resilience4j)
- [ ] Validate external API integrations
- [ ] Check file upload/download functionality
- [ ] Verify email sending
- [ ] Test background job processing

### 9.2 Alerting Rules

Update monitoring alerts for Java 17 and Boot 3 specific metrics:

```yaml
# Prometheus alerting rules
groups:
  - name: spring_boot_3
    rules:
      - alert: HighMemoryUsage
        expr: jvm_memory_used_bytes{area="heap"} / jvm_memory_max_bytes{area="heap"} > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High heap memory usage"
          
      - alert: HighGCPauseTime
        expr: rate(jvm_gc_pause_seconds_sum[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High GC pause time"
          
      - alert: HighErrorRate
        expr: rate(http_server_requests_seconds_count{status="5xx"}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
```

### 9.3 Performance Validation

Compare metrics before and after migration:

| Metric | Java 11 + Boot 2.7 | Java 17 + Boot 3.2 | Change |
|--------|-------------------|-------------------|--------|
| Startup Time | | | |
| Memory (Heap) | | | |
| Memory (Total) | | | |
| GC Pause (p99) | | | |
| API Response (p95) | | | |
| Throughput (RPS) | | | |

### 9.4 Smoke Tests

```bash
#!/bin/bash
# smoke-test.sh

BASE_URL="http://localhost:8080"

# Health check
curl -f "$BASE_URL/actuator/health" || exit 1

# Info endpoint
curl -f "$BASE_URL/actuator/info" || exit 1

# Main API endpoints
curl -f "$BASE_URL/api/users" || exit 1
curl -f -X POST "$BASE_URL/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@example.com"}' || exit 1

echo "All smoke tests passed!"
```

---

## Phase 10: Rollout Strategy

### 10.1 Staged Rollout

1. **Dev Environment**: 
   - Deploy and monitor for 1 week
   - Run full test suite
   - Performance testing

2. **QA/Staging**: 
   - Full regression testing
   - Load testing
   - Security testing
   - Monitor for 3-5 days

3. **Canary Deployment**: 
   - Deploy to 10% of production traffic
   - Monitor for 24-48 hours
   - Gradually increase to 50% if stable

4. **Full Production**: 
   - Deploy to remaining 50%
   - Monitor closely for 72 hours

### 10.2 Rollback Plan

**Prepare rollback artifacts**:
- Keep Spring Boot 2.7 branch available
- Maintain database backup before migration
- Document rollback procedures

**Rollback triggers**:
- Error rate > 2x baseline
- Memory usage > 95% for 10+ minutes
- Critical feature failure
- Security vulnerability discovered

**Rollback procedure**:
```bash
# 1. Stop new version
kubectl rollout undo deployment/myapp

# 2. Restore database (if schema changed)
psql -U postgres -d mydb < backup_pre_migration.sql

# 3. Deploy old version
kubectl set image deployment/myapp app=myapp:2.7-java11

# 4. Verify rollback
curl http://app/actuator/info | grep "2.7"
```

### 10.3 Communication Plan

- [ ] Notify stakeholders of migration schedule
- [ ] Set up status page for migration progress
- [ ] Prepare incident response team
- [ ] Create communication templates for issues

---

## Common Pitfalls & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| `ClassNotFoundException: javax.servlet.Filter` | Missed javax → jakarta migration | Search codebase for `import javax.` and replace with `jakarta.` |
| Security config not working | Still using `WebSecurityConfigurerAdapter` | Migrate to `SecurityFilterChain` bean with Lambda DSL |
| Tests failing with serialization errors | Jackson version incompatibility | Update Jackson to 2.15+ and check custom serializers |
| 404 on trailing slash URLs | Default Spring MVC behavior changed | Configure `setUseTrailingSlashMatch(true)` or update clients |
| Database schema changes unexpectedly | Hibernate 6 schema generation differences | Review and lock schema generation: `spring.jpa.hibernate.ddl-auto=validate` |
| Missing distributed traces | Spring Cloud Sleuth removed | Replace with Micrometer Tracing and configure Zipkin/Prometheus |
| Enum values stored as integers | Hibernate 6 default enum handling | Add `@Enumerated(EnumType.STRING)` explicitly |
| `UnsupportedOperationException` in queries | Stricter HQL parsing in Hibernate 6 | Review and fix custom JPQL queries |
| `NoSuchMethodError` for repository methods | `findOne()` removed from Spring Data | Replace with `findById()` |
| Application won't start with reflection error | Java 17 strong encapsulation | Add `--add-opens` flags or update libraries |
| Slower startup than expected | Too many auto-configurations | Enable lazy initialization or exclude unused auto-configs |
| Memory leak after migration | Changed GC behavior or connection pooling | Profile with JVisualVM and adjust HikariCP settings |
| OAuth2 authentication failing | Security 6 OAuth2 changes | Update OAuth2 client configuration for new DSL |
| Actuator endpoints not accessible | Changed exposure defaults | Explicitly configure `management.endpoints.web.exposure.include` |
| Custom metrics not showing | Micrometer API changes | Update to use `ObservationRegistry` and `MeterRegistry` |

---

## Complete Migration Checklist

### Pre-Migration (Phase 0-1)
- [ ] Risk assessment completed
- [ ] Migration timeline approved (4-8 weeks typical)
- [ ] Baseline metrics documented
- [ ] Rollback plan created
- [ ] Upgraded to Spring Boot 2.7.x
- [ ] Fixed all deprecations in 2.7
- [ ] Audited dependencies for Jakarta compatibility
- [ ] Test coverage verified (>70%)

### Java 17 Migration (Phase 2)
- [ ] Updated build files to Java 17
- [ ] Updated IDE to support Java 17
- [ ] Updated CI/CD pipelines to Java 17
- [ ] Addressed strong encapsulation issues
- [ ] Removed deprecated Java APIs
- [ ] Reviewed and updated GC flags
- [ ] Removed SecurityManager usage
- [ ] Applied Java 17 features (Records, Text Blocks, etc.)

### Jakarta Migration (Phase 3)
- [ ] Ran OpenRewrite migration
- [ ] Manually verified all `javax.*` → `jakarta.*` changes
- [ ] Updated Lombok to 1.18.30+
- [ ] Updated MapStruct to 1.5.5+
- [ ] Updated database drivers
- [ ] Updated cloud SDKs (AWS, GCP, Azure)
- [ ] Updated Jackson to 2.15+

### Spring Boot 3 Migration (Phase 4)
- [ ] Updated to Spring Boot 3.2.x
- [ ] Added properties migrator (temporarily)
- [ ] Updated all configuration properties
- [ ] Migrated Spring Security to `SecurityFilterChain`
- [ ] Fixed enum handling for Hibernate 6
- [ ] Addressed trailing slash URL matching
- [ ] Updated Spring Data repository methods
- [ ] Migrated `META-INF/spring.factories` to new format
- [ ] Updated Spring Cloud to 2023.0.0+
- [ ] Removed properties migrator before production

### Infrastructure (Phase 5)
- [ ] Updated Docker base images to Java 17
- [ ] Updated Flyway to 9.0+
- [ ] Updated Liquibase to 4.20+
- [ ] Configured Micrometer Tracing (replaced Sleuth)
- [ ] Updated APM agents
- [ ] Verified TestContainers compatibility
- [ ] Updated all test dependencies
- [ ] Run full regression test suite

### Security (Phase 6)
- [ ] Ran OWASP dependency check
- [ ] Fixed all high/critical vulnerabilities
- [ ] Updated security headers configuration
- [ ] Verified CORS configuration
- [ ] Tested authentication and authorization

### Performance (Phase 7)
- [ ] Optimized JVM flags for Java 17
- [ ] Configured connection pooling
- [ ] Considered CDS for faster startup
- [ ] Evaluated GraalVM Native Image (optional)
- [ ] Benchmarked performance vs. baseline

### Documentation (Phase 8)
- [ ] Updated README with new versions
- [ ] Updated developer setup guide
- [ ] Documented migration issues and solutions
- [ ] Created/updated runbooks
- [ ] Conducted team training sessions

### Deployment (Phase 9-10)
- [ ] Deployed to dev environment
- [ ] Monitored dev for 1 week
- [ ] Deployed to staging/QA
- [ ] Completed full regression testing
- [ ] Deployed canary (10% traffic)
- [ ] Monitored canary for 24-48 hours
- [ ] Rolled out to full production
- [ ] Monitored production for 72 hours
- [ ] Validated all critical features

### Post-Migration (Phase 9)
- [ ] Compared performance metrics to baseline
- [ ] Updated alerting rules
- [ ] Removed temporary migration code
- [ ] Archived old branches
- [ ] Documented lessons learned
- [ ] Celebrated success! 🎉

---

## Tools & Resources

### Automated Migration Tools

1. **OpenRewrite** (Primary tool)
   - Website: https://docs.openrewrite.org
   - Recipe: `org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_0`

2. **IntelliJ IDEA Migrator**
   - Built-in: Refactor → Migrate Packages and Classes

3. **Spring Boot Migrator** (Community project)
   - GitHub: https://github.com/spring-projects-experimental/spring-boot-migrator

### Testing & Analysis Tools

```bash
# Dependency analysis
mvn dependency:tree
mvn dependency:analyze
mvn versions:display-dependency-updates

# Security scanning
mvn org.owasp:dependency-check-maven:check
snyk test

# Performance testing
ab -n 1000 -c 10 http://localhost:8080/api/endpoint
```

### Validation Script

```bash
#!/bin/bash
# migration-validator.sh

echo "=== Spring Boot 3 Migration Validator ==="

# Check Java version
echo "Checking Java version..."
java -version 2>&1 | grep "version \"17" || { 
    echo "❌ Java 17 required"; 
    exit 1; 
}
echo "✓ Java 17 detected"

# Check for javax imports
echo "Checking for javax imports..."
if find src -name "*.java" -exec grep -l "import javax\." {} \; | grep -q .; then
    echo "❌ Found javax imports - should be jakarta"
    find src -name "*.java" -exec grep -l "import javax\." {} \;
    exit 1
fi
echo "✓ No javax imports found"

# Check Spring Boot version
echo "Checking Spring Boot version..."
if grep -q "<version>3\." pom.xml; then
    echo "✓ Spring Boot 3.x detected"
else
    echo "❌ Spring Boot 3.x required"
    exit 1
fi

# Check for WebSecurityConfigurerAdapter
echo "Checking for deprecated security classes..."
if find src -name "*.java" -exec grep -l "extends WebSecurityConfigurerAdapter" {} \; | grep -q .; then
    echo "❌ Found WebSecurityConfigurerAdapter - deprecated in Boot 3"
    exit 1
fi
echo "✓ No deprecated security classes found"

# Check for spring.factories
echo "Checking for old auto-configuration format..."
if [ -f "src/main/resources/META-INF/spring.factories" ]; then
    echo "⚠️  Found spring.factories - should migrate to AutoConfiguration.imports"
fi

echo ""
echo "=== Validation Summary ==="
echo "✓ All critical checks passed"
echo "Ready for Spring Boot 3 migration"
```

### Official Documentation

- [Spring Boot 3.0 Migration Guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.0-Migration-Guide)
- [Spring Security 6 Documentation](https://docs.spring.io/spring-security/reference/index.html)
- [Jakarta EE 9 Migration](https://jakarta.ee/specifications/platform/9/)
- [Java 17 Release Notes](https://openjdk.org/projects/jdk/17/)
- [Hibernate 6 Migration Guide](https://docs.jboss.org/hibernate/orm/6.0/migration-guide/migration-guide.html)
- [Micrometer Documentation](https://micrometer.io/docs)

---

## Final Recommendations

### Timeline Expectations

| Application Size | Expected Duration |
|-----------------|-------------------|
| Small (< 50k LOC) | 2-3 weeks |
| Medium (50k-200k LOC) | 4-6 weeks |
| Large (200k-500k LOC) | 6-10 weeks |
| Enterprise (> 500k LOC) | 10-16 weeks |

### Success Factors

1. **Don't skip Spring Boot 2.7** - It's your safety net
2. **Use OpenRewrite** - Saves 60-80% of manual work
3. **Test extensively** - Especially security and database layers
4. **Monitor closely** - First 72 hours in production are critical
5. **Budget extra time** - Complex apps always have surprises
6. **Document everything** - Future you will thank present you
7. **Train your team** - New patterns and APIs require learning

### When to Migrate

**Good reasons**:
- Security updates (Java 11 EOL: September 2024)
- Performance improvements
- New feature requirements
- Long-term maintainability

**Bad reasons**:
- "Just because" (no business value)
- Right before a major release
- Without adequate testing resources

### Risk Mitigation

- Start with non-critical services
- Use feature flags for gradual rollout
- Maintain parallel environments during migration
- Have experienced team members lead the effort
- Budget 20-30% extra time for unknowns

---

## Conclusion

Migrating from Java 11 to 17 and Spring Boot 2.x to 3.x is a substantial undertaking, but the benefits are significant:

**Benefits**:
- ✅ Extended LTS support (Java 17 until 2029)
- ✅ Better performance (10-30% improvement typical)
- ✅ Modern language features (Records, Pattern Matching, Sealed Classes)
- ✅ Improved security
- ✅ Better observability with Micrometer
- ✅ Future-proof architecture

**Challenges**:
- ⚠️ Breaking changes require careful testing
- ⚠️ Team training needed
- ⚠️ Potential third-party library issues
- ⚠️ Initial time investment

With proper planning, the right tools, and this comprehensive guide, your migration will be successful. The key is to be methodical, test thoroughly, and not rush the process.

**Good luck with your migration!** 

