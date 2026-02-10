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



---

# Additional Upgrade: Java 17 → Java 25 Migration Guide

## Overview
Migrating from Java 17 (LTS) to Java 25 (non-LTS) is significantly simpler than the Java 11→17 migration. This guide covers all necessary steps.

---

## Phase 1: Pre-Migration Assessment

### 1.1 Version Compatibility Check
- [ ] Verify Spring Boot 3.2+ supports Java 25
- [ ] Check all third-party libraries for Java 25 compatibility
- [ ] Review CI/CD pipeline Java version support

### 1.2 Java 25 Considerations
⚠️ **Important**: Java 25 is **non-LTS** (Standard Support until March 2026)
- For production: Consider staying on **Java 21 LTS** (support until 2029)
- Java 25 good for: Experimentation, non-critical applications, cutting-edge features

---

## Phase 2: Build Configuration Updates

### 2.1 Update Maven Configuration

**pom.xml**:
```xml
<properties>
    <java.version>25</java.version>
    <maven.compiler.source>25</maven.compiler.source>
    <maven.compiler.target>25</maven.compiler.target>
    <maven.compiler.release>25</maven.compiler.release>
</properties>

<!-- If using preview features -->
<properties>
    <maven.compiler.enablePreview>true</maven.compiler.enablePreview>
</properties>

<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-compiler-plugin</artifactId>
            <version>3.13.0</version>
            <configuration>
                <source>25</source>
                <target>25</target>
                <enablePreview>true</enablePreview> <!-- If needed -->
            </configuration>
        </plugin>
        
        <!-- Update Surefire for tests -->
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>3.2.5</version>
            <configuration>
                <argLine>--enable-preview</argLine> <!-- If using preview features -->
            </configuration>
        </plugin>
    </plugins>
</build>
```

### 2.2 Update Gradle Configuration

**build.gradle**:
```gradle
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.3.0'
    id 'io.spring.dependency-management' version '1.1.4'
}

java {
    sourceCompatibility = JavaVersion.VERSION_25
    targetCompatibility = JavaVersion.VERSION_25
}

// If using preview features
tasks.withType(JavaCompile) {
    options.compilerArgs += ['--enable-preview']
}

tasks.withType(Test) {
    jvmArgs += ['--enable-preview']
}
```

**gradle.properties**:
```properties
org.gradle.java.home=/path/to/jdk-25
```

---

## Phase 3: Development Environment Setup

### 3.1 Install JDK 25

**Download Options**:
```bash
# Oracle JDK
# Download from: https://www.oracle.com/java/technologies/downloads/#java25

# Eclipse Temurin
# Download from: https://adoptium.net/

# Using SDKMAN (Linux/Mac)
sdk install java 25-tem
sdk use java 25-tem

# Using Homebrew (Mac)
brew install openjdk@25

# Verify installation
java -version
# Should show: java version "25"
```

### 3.2 Update IDE

**IntelliJ IDEA**:
- Version: 2024.1 or later
- File → Project Structure → Project SDK → Add JDK → Select JDK 25
- File → Project Structure → Project Language Level → 25 (Preview)
- Settings → Build, Execution, Deployment → Compiler → Java Compiler → Set to 25

**Eclipse**:
- Version: 2024-03 or later
- Help → Install New Software → Add Java 25 support
- Project → Properties → Java Compiler → Compiler compliance level: 25

**VS Code**:
```json
// settings.json
{
    "java.configuration.runtimes": [
        {
            "name": "JavaSE-25",
            "path": "/path/to/jdk-25"
        }
    ],
    "java.jdt.ls.java.home": "/path/to/jdk-25"
}
```

---

## Phase 4: CI/CD Pipeline Updates

### 4.1 GitHub Actions

**.github/workflows/build.yml**:
```yaml
name: Java CI

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up JDK 25
      uses: actions/setup-java@v4
      with:
        java-version: '25'
        distribution: 'temurin'
        
    - name: Build with Maven
      run: mvn clean verify
      
    - name: Run tests
      run: mvn test
```

### 4.2 Jenkins

**Jenkinsfile**:
```groovy
pipeline {
    agent {
        docker {
            image 'eclipse-temurin:25-jdk'
        }
    }
    
    stages {
        stage('Build') {
            steps {
                sh 'java -version'
                sh 'mvn clean package'
            }
        }
        
        stage('Test') {
            steps {
                sh 'mvn test'
            }
        }
    }
}
```

### 4.3 GitLab CI

**.gitlab-ci.yml**:
```yaml
image: eclipse-temurin:25-jdk

stages:
  - build
  - test

build:
  stage: build
  script:
    - java -version
    - ./mvnw clean package
  artifacts:
    paths:
      - target/*.jar

test:
  stage: test
  script:
    - ./mvnw test
```

---

## Phase 5: Leverage New Java Features (18-25)

### 5.1 Pattern Matching for Switch (Java 21 - Standard)

```java
// Before (Java 17)
public String formatValue(Object obj) {
    if (obj instanceof String s) {
        return "String: " + s;
    } else if (obj instanceof Integer i) {
        return "Integer: " + i;
    } else if (obj instanceof Double d) {
        return "Double: " + d;
    } else {
        return "Unknown";
    }
}

// After (Java 25)
public String formatValue(Object obj) {
    return switch (obj) {
        case String s -> "String: " + s;
        case Integer i -> "Integer: " + i;
        case Double d -> "Double: " + d;
        case null -> "Null value";
        default -> "Unknown";
    };
}

// With guards
public String classify(Object obj) {
    return switch (obj) {
        case String s when s.length() > 10 -> "Long string";
        case String s -> "Short string";
        case Integer i when i > 100 -> "Large number";
        case Integer i -> "Small number";
        default -> "Other";
    };
}
```

### 5.2 Record Patterns (Java 21 - Standard)

```java
record Point(int x, int y) {}
record Circle(Point center, int radius) {}
record Rectangle(Point topLeft, Point bottomRight) {}

// Deconstruct records in patterns
public void processShape(Object shape) {
    switch (shape) {
        case Circle(Point(int x, int y), int r) ->
            System.out.printf("Circle at (%d,%d) with radius %d%n", x, y, r);
            
        case Rectangle(Point(int x1, int y1), Point(int x2, int y2)) ->
            System.out.printf("Rectangle from (%d,%d) to (%d,%d)%n", x1, y1, x2, y2);
            
        default ->
            System.out.println("Unknown shape");
    }
}

// Nested patterns
if (shape instanceof Circle(Point(var x, var y), var radius)) {
    System.out.println("Circle center: " + x + "," + y);
}
```

### 5.3 Sequenced Collections (Java 21 - Standard)

```java
// New methods for List, Set, Map

// List operations
List<String> list = new ArrayList<>();
list.addFirst("first");    // Add at beginning
list.addLast("last");      // Add at end
String first = list.getFirst();  // Get first element
String last = list.getLast();    // Get last element
list.removeFirst();        // Remove first
list.removeLast();         // Remove last
List<String> reversed = list.reversed();  // Reversed view

// LinkedHashSet operations
LinkedHashSet<String> set = new LinkedHashSet<>();
set.addFirst("a");
set.addLast("z");
String firstInSet = set.getFirst();

// LinkedHashMap operations
LinkedHashMap<String, Integer> map = new LinkedHashMap<>();
map.putFirst("first", 1);
map.putLast("last", 100);
Entry<String, Integer> firstEntry = map.firstEntry();
Entry<String, Integer> lastEntry = map.lastEntry();
```

### 5.4 Virtual Threads (Java 21 - Standard)

```java
// Create virtual threads (extremely lightweight)
Thread vThread = Thread.ofVirtual().start(() -> {
    System.out.println("Running on virtual thread");
});

// Virtual thread executor
try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
    // Can handle millions of virtual threads
    for (int i = 0; i < 100_000; i++) {
        executor.submit(() -> {
            // Each task runs on its own virtual thread
            performTask();
        });
    }
} // Auto-shutdown

// Spring Boot integration
@Configuration
public class VirtualThreadConfig {
    
    @Bean
    public AsyncTaskExecutor applicationTaskExecutor() {
        return new TaskExecutorAdapter(Executors.newVirtualThreadPerTaskExecutor());
    }
    
    // For Tomcat
    @Bean
    public TomcatProtocolHandlerCustomizer<?> protocolHandlerVirtualThreadExecutor() {
        return protocolHandler -> {
            protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        };
    }
}

// Enable in application.properties (Spring Boot 3.2+)
// spring.threads.virtual.enabled=true
```

### 5.5 String Templates (Java 21 Preview → Java 23 Standard)

```java
// String interpolation
String name = "John";
int age = 30;

// Instead of String.format
String oldWay = String.format("Name: %s, Age: %d", name, age);

// Use String Templates
String newWay = STR."Name: \{name}, Age: \{age}";

// Complex expressions
String message = STR."""
    User Details:
    Name: \{name.toUpperCase()}
    Age: \{age}
    Status: \{age >= 18 ? "Adult" : "Minor"}
    """;

// With calculations
int x = 10, y = 20;
String calc = STR."Sum: \{x + y}, Product: \{x * y}";

// JSON generation
String json = STR."""
    {
        "name": "\{name}",
        "age": \{age},
        "active": \{true}
    }
    """;
```

### 5.6 Unnamed Patterns and Variables (Java 22 - Standard)

```java
// Use _ for unused variables/patterns

// In pattern matching
record Point(int x, int y) {}

switch (point) {
    case Point(int x, _) -> System.out.println("X: " + x);  // Don't care about y
    case Point(_, int y) -> System.out.println("Y: " + y);  // Don't care about x
}

// In lambda expressions
list.forEach(_ -> System.out.println("Processing item"));

// In catch blocks (when exception not used)
try {
    riskyOperation();
} catch (IOException _) {
    System.out.println("IO Error occurred");
}

// In enhanced for loops (when element not used)
for (int _ : List.of(1, 2, 3)) {
    performAction();  // Execute 3 times, don't care about values
}
```

### 5.7 Scoped Values (Java 21+)

```java
// Better alternative to ThreadLocal
public class UserContext {
    public static final ScopedValue<User> CURRENT_USER = ScopedValue.newInstance();
    public static final ScopedValue<String> REQUEST_ID = ScopedValue.newInstance();
}

// Set and use scoped values
public void handleRequest(User user, String requestId) {
    ScopedValue.runWhere(UserContext.CURRENT_USER, user,
        () -> ScopedValue.runWhere(UserContext.REQUEST_ID, requestId,
            () -> {
                // CURRENT_USER and REQUEST_ID available here
                processRequest();
            }
        )
    );
}

// Access in nested methods
public void processRequest() {
    User currentUser = UserContext.CURRENT_USER.get();
    String requestId = UserContext.REQUEST_ID.get();
    
    // Use values
    auditLog.log("User: " + currentUser + ", Request: " + requestId);
}

// Spring Boot integration
@Component
public class ScopedValueInterceptor implements HandlerInterceptor {
    
    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) {
        String requestId = UUID.randomUUID().toString();
        ScopedValue.runWhere(UserContext.REQUEST_ID, requestId, () -> {
            // Handle request
        });
        return true;
    }
}
```

### 5.8 Foreign Function & Memory API (Java 22 - Standard)

```java
// Direct memory access and native function calls
import java.lang.foreign.*;

// Allocate off-heap memory
try (Arena arena = Arena.ofConfined()) {
    MemorySegment segment = arena.allocate(100);
    segment.setAtIndex(ValueLayout.JAVA_INT, 0, 42);
    int value = segment.getAtIndex(ValueLayout.JAVA_INT, 0);
}

// Call native C functions
Linker linker = Linker.nativeLinker();
SymbolLookup stdlib = linker.defaultLookup();

// strlen function
MethodHandle strlen = linker.downcallHandle(
    stdlib.find("strlen").orElseThrow(),
    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS)
);
```

### 5.9 Structured Concurrency (Java 21+ Preview)

```java
// Better concurrent programming
import java.util.concurrent.StructuredTaskScope;

public class DataAggregator {
    
    record UserData(String profile, List<String> orders, List<String> preferences) {}
    
    public UserData fetchUserData(String userId) throws Exception {
        try (var scope = new StructuredTaskScope.ShutdownOnFailure()) {
            
            // Launch concurrent tasks
            Future<String> profile = scope.fork(() -> fetchProfile(userId));
            Future<List<String>> orders = scope.fork(() -> fetchOrders(userId));
            Future<List<String>> prefs = scope.fork(() -> fetchPreferences(userId));
            
            // Wait for all to complete or fail
            scope.join();
            scope.throwIfFailed();
            
            // All succeeded, combine results
            return new UserData(
                profile.resultNow(),
                orders.resultNow(),
                prefs.resultNow()
            );
        }
    }
    
    private String fetchProfile(String userId) { /* ... */ return ""; }
    private List<String> fetchOrders(String userId) { /* ... */ return List.of(); }
    private List<String> fetchPreferences(String userId) { /* ... */ return List.of(); }
}
```

---

## Phase 6: Update Dependencies

### 6.1 Core Dependencies

```xml
<!-- Ensure latest versions compatible with Java 25 -->

<!-- Lombok -->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.18.32</version>
    <scope>provided</scope>
</dependency>

<!-- MapStruct -->
<dependency>
    <groupId>org.mapstruct</groupId>
    <artifactId>mapstruct</artifactId>
    <version>1.6.0</version>
</dependency>

<!-- Jackson -->
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.17.0</version>
</dependency>

<!-- Apache Commons -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-lang3</artifactId>
    <version>3.14.0</version>
</dependency>
```

### 6.2 Testing Libraries

```xml
<!-- JUnit 5 -->
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.10.2</version>
    <scope>test</scope>
</dependency>

<!-- Mockito -->
<dependency>
    <groupId>org.mockito</groupId>
    <artifactId>mockito-core</artifactId>
    <version>5.11.0</version>
    <scope>test</scope>
</dependency>

<!-- AssertJ -->
<dependency>
    <groupId>org.assertj</groupId>
    <artifactId>assertj-core</artifactId>
    <version>3.25.3</version>
    <scope>test</scope>
</dependency>

<!-- TestContainers -->
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>testcontainers</artifactId>
    <version>1.19.7</version>
    <scope>test</scope>
</dependency>
```

---

## Phase 7: JVM Tuning for Java 25

### 7.1 Garbage Collection Updates

```bash
# Generational ZGC (major improvement in Java 21+)
java -XX:+UseZGC -XX:+ZGenerational -jar app.jar

# G1GC with Java 25 improvements (still default)
java -XX:+UseG1GC \
     -XX:MaxGCPauseMillis=200 \
     -XX:G1HeapRegionSize=16m \
     -XX:InitiatingHeapOccupancyPercent=45 \
     -jar app.jar

# For low-latency applications
java -XX:+UseZGC \
     -XX:+ZGenerational \
     -XX:ZCollectionInterval=5 \
     -Xmx4g \
     -jar app.jar
```

### 7.2 Optimized JVM Flags for Containers

```bash
# Docker/Kubernetes optimized
java -XX:+UseContainerSupport \
     -XX:MaxRAMPercentage=75.0 \
     -XX:InitialRAMPercentage=50.0 \
     -XX:+UseZGC \
     -XX:+ZGenerational \
     -XX:+AlwaysPreTouch \
     -jar app.jar
```

### 7.3 Virtual Thread Optimizations

```properties
# application.properties (Spring Boot 3.2+)
spring.threads.virtual.enabled=true

# JVM flags for virtual threads
# -Djdk.virtualThreadScheduler.parallelism=100
# -Djdk.virtualThreadScheduler.maxPoolSize=256
```

---

## Phase 8: Docker Image Updates

### 8.1 Update Dockerfile

```dockerfile
# Multi-stage build
FROM eclipse-temurin:25-jdk-alpine AS build
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN ./mvnw clean package -DskipTests

# Runtime
FROM eclipse-temurin:25-jre-alpine

WORKDIR /app

# Add non-root user
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

COPY --from=build /app/target/*.jar app.jar

# Optimized JVM flags
ENV JAVA_OPTS="-XX:+UseZGC -XX:+ZGenerational -XX:MaxRAMPercentage=75.0"

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
```

### 8.2 Docker Compose Update

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    image: myapp:java25
    ports:
      - "8080:8080"
    environment:
      - JAVA_OPTS=-XX:+UseZGC -XX:+ZGenerational -Xmx2g
      - SPRING_PROFILES_ACTIVE=production
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
```

---

## Phase 9: Testing & Validation

### 9.1 Compatibility Testing

```bash
# Run full test suite
mvn clean test

# Integration tests
mvn verify

# Check for deprecation warnings
mvn compile -Xlint:deprecation
```

### 9.2 Performance Benchmarking

```java
// JMH Benchmarking
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Fork(value = 2, jvmArgs = {"-Xms2G", "-Xmx2G"})
@Warmup(iterations = 3)
@Measurement(iterations = 5)
public class Java25Benchmark {
    
    @Benchmark
    public void testVirtualThreads() throws InterruptedException {
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < 10000; i++) {
                executor.submit(() -> {
                    Thread.sleep(Duration.ofMillis(100));
                });
            }
        }
    }
    
    @Benchmark
    public void testPatternMatching(Object obj) {
        String result = switch (obj) {
            case String s -> "String: " + s;
            case Integer i -> "Integer: " + i;
            default -> "Other";
        };
    }
}
```

### 9.3 Migration Validation Script

```bash
#!/bin/bash
# validate-java25.sh

echo "=== Java 25 Migration Validator ==="

# Check Java version
echo "Checking Java version..."
java -version 2>&1 | grep "version \"25" || {
    echo "❌ Java 25 required"
    exit 1
}
echo "✓ Java 25 detected"

# Check Spring Boot compatibility
echo "Checking Spring Boot version..."
if grep -q "<version>3\.[2-9]" pom.xml || grep -q "<version>3\.1[0-9]" pom.xml; then
    echo "✓ Spring Boot 3.2+ detected (compatible with Java 25)"
else
    echo "⚠️  Upgrade to Spring Boot 3.2+ recommended"
fi

# Build test
echo "Testing build..."
mvn clean compile || {
    echo "❌ Build failed"
    exit 1
}
echo "✓ Build successful"

# Run tests
echo "Running tests..."
mvn test || {
    echo "❌ Tests failed"
    exit 1
}
echo "✓ Tests passed"

# Check for virtual thread usage (optional)
echo "Checking for virtual thread support..."
if grep -r "newVirtualThreadPerTaskExecutor\|Thread.ofVirtual" src/; then
    echo "✓ Virtual threads in use"
else
    echo "ℹ️  No virtual threads detected (optional feature)"
fi

echo ""
echo "=== Migration Summary ==="
echo "✓ Java 25 migration successful"
echo "Application ready for deployment"
```

---

## Phase 10: Deployment Considerations

### 10.1 Production Deployment Checklist

- [ ] All tests passing on Java 25
- [ ] Performance benchmarks completed
- [ ] Docker images built and tested
- [ ] CI/CD pipelines updated
- [ ] Monitoring/APM agents compatible
- [ ] Rollback plan prepared
- [ ] Team trained on new features

### 10.2 Monitoring Setup

```yaml
# Prometheus JVM metrics (works with Java 25)
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  metrics:
    tags:
      application: ${spring.application.name}
      java_version: "25"
    export:
      prometheus:
        enabled: true
```

### 10.3 Rollback Strategy

```bash
# Keep Java 17 version tagged
docker tag myapp:latest myapp:java17-backup

# If issues arise, rollback
docker stop myapp-java25
docker run myapp:java17-backup
```

---

## Phase 11: Performance Optimization

### 11.1 Enable Virtual Threads in Spring Boot

```java
@Configuration
public class VirtualThreadConfiguration {
    
    @Bean
    public TomcatProtocolHandlerCustomizer<?> protocolHandlerVirtualThreadExecutorCustomizer() {
        return protocolHandler -> {
            protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        };
    }
    
    @Bean
    public AsyncConfigurer asyncConfigurer() {
        return new AsyncConfigurer() {
            @Override
            public Executor getAsyncExecutor() {
                return Executors.newVirtualThreadPerTaskExecutor();
            }
        };
    }
}
```

```properties
# application.properties (Spring Boot 3.2+)
spring.threads.virtual.enabled=true
```

### 11.2 Optimize Garbage Collection

```properties
# For low-latency apps
spring.application.jvm-args=-XX:+UseZGC -XX:+ZGenerational

# Monitor GC
-Xlog:gc*:file=gc.log:time,uptime:filecount=5,filesize=100M
```

---

## Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| Preview features not working | Not enabled in compiler | Add `--enable-preview` to Maven/Gradle config |
| IDE shows errors for new syntax | Language level not set | Update IDE language level to 25 |
| Tests failing | Surefire plugin needs preview flag | Add `--enable-preview` to Surefire argLine |
| Docker build fails | Base image doesn't have JDK 25 | Use `eclipse-temurin:25-jdk` |
| Virtual threads not working | Spring Boot < 3.2 | Upgrade to Spring Boot 3.2+ |
| Performance regression | Wrong GC selected | Try ZGC with `-XX:+ZGenerational` |

---

## Complete Migration Checklist

### Pre-Migration
- [ ] Verify Spring Boot 3.2+ compatibility
- [ ] Check all dependencies support Java 25
- [ ] Review team readiness
- [ ] Create rollback plan

### Configuration
- [ ] Updated `pom.xml` / `build.gradle` to Java 25
- [ ] Configured preview features if needed
- [ ] Updated Maven/Gradle plugins

### Development Environment
- [ ] Installed JDK 25
- [ ] Updated IDE to support Java 25
- [ ] Configured IDE language level to 25

### CI/CD
- [ ] Updated GitHub Actions / Jenkins / GitLab CI
- [ ] Updated Docker base images
- [ ] Tested build pipeline

### Code Updates
- [ ] Refactored to use pattern matching for switch
- [ ] Applied record patterns where applicable
- [ ] Used sequenced collections
- [ ] Implemented virtual threads for I/O operations
- [ ] Applied string templates (if using preview)

### Dependencies
- [ ] Updated Lombok to 1.18.32+
- [ ] Updated MapStruct to 1.6.0+
- [ ] Updated testing libraries
- [ ] Verified all third-party libraries

### Performance
- [ ] Configured optimal GC (ZGC recommended)
- [ ] Enabled virtual threads in Spring Boot
- [ ] Optimized JVM flags for containers
- [ ] Benchmarked performance

### Testing
- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Performance tests completed
- [ ] Load testing done

### Deployment
- [ ] Docker images built and tested
- [ ] Kubernetes manifests updated
- [ ] Monitoring configured
- [ ] Documentation updated
- [ ] Team trained

---

## Timeline Estimate

| Application Size | Estimated Duration |
|-----------------|-------------------|
| Small (< 50k LOC) | 3-5 days |
| Medium (50k-200k LOC) | 1-2 weeks |
| Large (200k+ LOC) | 2-3 weeks |

---

## Key Benefits of Java 25

✅ **Pattern matching for switch** - Cleaner conditional logic  
✅ **Record patterns** - Elegant data extraction  
✅ **Sequenced collections** - Better list/set operations  
✅ **Virtual threads** - Massive scalability improvement  
✅ **String templates** - Easier string interpolation  
✅ **Improved GC** - Better performance with Generational ZGC  
✅ **Foreign Function API** - Native code integration  
✅ **Scoped values** - Better than ThreadLocal  

---

## Final Recommendations

### ⚠️ Production Considerations

**Consider staying on Java 21 LTS if:**
- Production application requiring long-term support
- Risk-averse organization
- Limited testing resources

**Upgrade to Java 25 if:**
- Non-critical application
- Want to experiment with latest features
- Short-lived project (< 1 year)
- Can afford frequent upgrades

### Best Practices

1. **Test thoroughly** - Java 25 is stable but new
2. **Use virtual threads** - Biggest performance win
3. **Enable preview features selectively** - Only if needed
4. **Monitor closely** - First 2 weeks in production
5. **Plan for Java 26** - It's 6 months away (March 2025)

---

# Additional Upgrade: Java 17 → Java 21 LTS Migration Guide

## Overview
Migrating from Java 17 LTS to Java 21 LTS is a smart, production-ready upgrade. Both are LTS releases with extended support, making this a safe and recommended migration path.

**Java 21 LTS Support**: September 2023 - September 2031 (8 years)

---

## Phase 1: Pre-Migration Assessment

### 1.1 Why Upgrade to Java 21?

**Key Benefits**:
- ✅ Extended support until 2031 (vs 2029 for Java 17)
- ✅ **Virtual Threads** (Project Loom) - Production ready
- ✅ **Pattern Matching for Switch** - Standard feature
- ✅ **Record Patterns** - Standard feature
- ✅ **Sequenced Collections** - Better APIs
- ✅ **Generational ZGC** - Improved garbage collection
- ✅ Performance improvements (10-15% typical)
- ✅ Security enhancements

### 1.2 Compatibility Check

- [ ] Verify Spring Boot 3.1+ (recommended 3.2+)
- [ ] Check all third-party libraries for Java 21 compatibility
- [ ] Review CI/CD pipeline support
- [ ] Confirm Docker base image availability

**Spring Boot Compatibility**:
- Spring Boot 3.0+: Supports Java 21
- Spring Boot 3.1+: Optimized for Java 21
- Spring Boot 3.2+: Full Java 21 feature support (virtual threads, etc.)

---

## Phase 2: Build Configuration Updates

### 2.1 Update Maven Configuration

**pom.xml**:
```xml
<properties>
    <java.version>21</java.version>
    <maven.compiler.source>21</maven.compiler.source>
    <maven.compiler.target>21</maven.compiler.target>
    <maven.compiler.release>21</maven.compiler.release>
</properties>

<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-compiler-plugin</artifactId>
            <version>3.11.0</version>
            <configuration>
                <source>21</source>
                <target>21</target>
                <release>21</release>
            </configuration>
        </plugin>
        
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>3.1.2</version>
        </plugin>
    </plugins>
</build>
```

### 2.2 Update Gradle Configuration

**build.gradle**:
```gradle
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.2'
    id 'io.spring.dependency-management' version '1.1.4'
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

// Or simple version
java {
    sourceCompatibility = '21'
    targetCompatibility = '21'
}
```

**gradle.properties**:
```properties
org.gradle.java.home=/path/to/jdk-21
```

---

## Phase 3: Development Environment Setup

### 3.1 Install JDK 21

**Download Options**:

```bash
# Eclipse Temurin (Recommended for production)
# Download from: https://adoptium.net/temurin/releases/?version=21

# Oracle JDK
# Download from: https://www.oracle.com/java/technologies/downloads/#java21

# Amazon Corretto
# Download from: https://aws.amazon.com/corretto/

# Using SDKMAN (Linux/Mac)
sdk install java 21.0.2-tem
sdk use java 21.0.2-tem

# Using Homebrew (Mac)
brew install openjdk@21

# Using apt (Ubuntu/Debian)
sudo apt update
sudo apt install openjdk-21-jdk

# Using yum (RHEL/CentOS)
sudo yum install java-21-openjdk-devel

# Verify installation
java -version
# Output: openjdk version "21.0.2" 2024-01-16 LTS
```

### 3.2 Update IDE

**IntelliJ IDEA**:
- **Minimum Version**: 2023.2 or later
- **Recommended**: 2023.3+

Steps:
1. File → Project Structure → Project
2. SDK: Add JDK → Select JDK 21
3. Language Level: 21 - Pattern matching for switch, record patterns
4. File → Settings → Build, Execution, Deployment → Compiler → Java Compiler
5. Project bytecode version: 21

**Eclipse**:
- **Minimum Version**: 2023-09 or later
- **Recommended**: 2023-12+

Steps:
1. Help → Check for Updates
2. Window → Preferences → Java → Installed JREs → Add JDK 21
3. Project → Properties → Java Compiler → Compiler compliance level: 21

**VS Code**:
```json
// .vscode/settings.json
{
    "java.configuration.runtimes": [
        {
            "name": "JavaSE-21",
            "path": "/path/to/jdk-21",
            "default": true
        }
    ],
    "java.jdt.ls.java.home": "/path/to/jdk-21"
}
```

---

## Phase 4: CI/CD Pipeline Updates

### 4.1 GitHub Actions

**.github/workflows/build.yml**:
```yaml
name: Java CI with Maven

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up JDK 21
      uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'
        cache: maven
        
    - name: Build with Maven
      run: mvn -B clean verify
      
    - name: Run tests
      run: mvn test
      
    - name: Build Docker image
      run: docker build -t myapp:latest .
```

### 4.2 Jenkins

**Declarative Pipeline (Jenkinsfile)**:
```groovy
pipeline {
    agent {
        docker {
            image 'eclipse-temurin:21-jdk'
            args '-v $HOME/.m2:/root/.m2'
        }
    }
    
    stages {
        stage('Verify Java') {
            steps {
                sh 'java -version'
            }
        }
        
        stage('Build') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }
        
        stage('Test') {
            steps {
                sh 'mvn test'
            }
            post {
                always {
                    junit 'target/surefire-reports/*.xml'
                }
            }
        }
        
        stage('Integration Test') {
            steps {
                sh 'mvn verify'
            }
        }
    }
}
```

**Scripted Pipeline**:
```groovy
node {
    docker.image('eclipse-temurin:21-jdk').inside {
        stage('Checkout') {
            checkout scm
        }
        
        stage('Build') {
            sh 'mvn clean package'
        }
        
        stage('Test') {
            sh 'mvn test'
        }
    }
}
```

### 4.3 GitLab CI

**.gitlab-ci.yml**:
```yaml
image: eclipse-temurin:21-jdk

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=$CI_PROJECT_DIR/.m2/repository"

cache:
  paths:
    - .m2/repository
    - target/

stages:
  - build
  - test
  - package

build:
  stage: build
  script:
    - java -version
    - ./mvnw clean compile

test:
  stage: test
  script:
    - ./mvnw test
  artifacts:
    reports:
      junit:
        - target/surefire-reports/TEST-*.xml

package:
  stage: package
  script:
    - ./mvnw package -DskipTests
  artifacts:
    paths:
      - target/*.jar
    expire_in: 1 week
```

### 4.4 Azure DevOps

**azure-pipelines.yml**:
```yaml
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: JavaToolInstaller@0
  inputs:
    versionSpec: '21'
    jdkArchitectureOption: 'x64'
    jdkSourceOption: 'PreInstalled'

- task: Maven@3
  inputs:
    mavenPomFile: 'pom.xml'
    goals: 'clean package'
    javaHomeOption: 'JDKVersion'
    jdkVersionOption: '21'
    
- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '**/surefire-reports/TEST-*.xml'
```

---

## Phase 5: Leverage Java 21 Features

### 5.1 Virtual Threads (Project Loom) - PRODUCTION READY ⭐

**The Killer Feature of Java 21**

Virtual threads are lightweight threads that dramatically improve application scalability for I/O-bound workloads.

**Traditional Platform Threads**:
```java
// Old way - limited to ~5,000 threads
ExecutorService executor = Executors.newFixedThreadPool(100);
for (int i = 0; i < 10000; i++) {
    executor.submit(() -> {
        // I/O operation
        callExternalApi();
    });
}
```

**Virtual Threads - New Way**:
```java
// New way - can handle MILLIONS of threads
try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
    for (int i = 0; i < 1_000_000; i++) {  // Yes, 1 million!
        executor.submit(() -> {
            // I/O operation runs on virtual thread
            callExternalApi();
        });
    }
} // Auto-shutdown
```

**Creating Virtual Threads**:
```java
// Method 1: Thread.ofVirtual()
Thread vThread = Thread.ofVirtual().start(() -> {
    System.out.println("Running on virtual thread: " + Thread.currentThread());
});

// Method 2: Thread.startVirtualThread()
Thread vThread2 = Thread.startVirtualThread(() -> {
    performTask();
});

// Method 3: Thread.ofVirtual().factory()
ThreadFactory factory = Thread.ofVirtual().factory();
Thread vThread3 = factory.newThread(() -> performTask());
vThread3.start();

// Method 4: Executor
ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
executor.submit(() -> performTask());
```

**Spring Boot 3.2+ Virtual Thread Integration**:

```properties
# application.properties
# Enable virtual threads for web requests (Spring Boot 3.2+)
spring.threads.virtual.enabled=true
```

```java
@Configuration
public class VirtualThreadConfig {
    
    // For Tomcat (default web server)
    @Bean
    public TomcatProtocolHandlerCustomizer<?> protocolHandlerVirtualThreadExecutorCustomizer() {
        return protocolHandler -> {
            protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        };
    }
    
    // For async methods
    @Bean
    public AsyncTaskExecutor applicationTaskExecutor() {
        return new TaskExecutorAdapter(Executors.newVirtualThreadPerTaskExecutor());
    }
    
    // For @Async
    @Bean
    public AsyncConfigurer asyncConfigurer() {
        return new AsyncConfigurer() {
            @Override
            public Executor getAsyncExecutor() {
                return Executors.newVirtualThreadPerTaskExecutor();
            }
        };
    }
}
```

**Real-World Example - API Gateway**:
```java
@RestController
@RequestMapping("/api")
public class AggregationController {
    
    @GetMapping("/user/{id}/dashboard")
    public UserDashboard getDashboard(@PathVariable Long id) {
        // With virtual threads, these all run concurrently without blocking platform threads
        try (var scope = new StructuredTaskScope.ShutdownOnFailure()) {
            
            Supplier<UserProfile> profileTask = scope.fork(() -> userService.getProfile(id));
            Supplier<List<Order>> ordersTask = scope.fork(() -> orderService.getOrders(id));
            Supplier<List<Notification>> notificationsTask = scope.fork(() -> notificationService.getNotifications(id));
            Supplier<AccountBalance> balanceTask = scope.fork(() -> billingService.getBalance(id));
            
            scope.join();           // Wait for all tasks
            scope.throwIfFailed();  // Throw if any failed
            
            return new UserDashboard(
                profileTask.get(),
                ordersTask.get(),
                notificationsTask.get(),
                balanceTask.get()
            );
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException("Failed to fetch dashboard", e);
        }
    }
}
```

**Database Connection Pooling with Virtual Threads**:
```properties
# Increase connection pool size (virtual threads can handle more)
spring.datasource.hikari.maximum-pool-size=50
spring.datasource.hikari.minimum-idle=20
```

**Performance Impact**:
- **Before (Platform Threads)**: ~5,000 concurrent requests
- **After (Virtual Threads)**: 100,000+ concurrent requests
- **Memory**: Each virtual thread ~1KB vs platform thread ~1MB

### 5.2 Pattern Matching for Switch (Standard in Java 21)

```java
// Before Java 21 - verbose instanceof chains
public String processValue(Object obj) {
    if (obj instanceof String s) {
        return "String of length: " + s.length();
    } else if (obj instanceof Integer i) {
        return "Integer: " + i;
    } else if (obj instanceof Long l) {
        return "Long: " + l;
    } else if (obj instanceof Double d) {
        return "Double: " + d;
    } else if (obj == null) {
        return "null value";
    } else {
        return "Unknown type";
    }
}

// Java 21 - elegant switch expressions
public String processValue(Object obj) {
    return switch (obj) {
        case String s -> "String of length: " + s.length();
        case Integer i -> "Integer: " + i;
        case Long l -> "Long: " + l;
        case Double d -> "Double: " + d;
        case null -> "null value";
        default -> "Unknown type";
    };
}

// With guards (when clauses)
public String classify(Object obj) {
    return switch (obj) {
        case String s when s.length() > 10 -> "Long string: " + s;
        case String s when s.isEmpty() -> "Empty string";
        case String s -> "Short string: " + s;
        
        case Integer i when i > 100 -> "Large number: " + i;
        case Integer i when i < 0 -> "Negative number: " + i;
        case Integer i -> "Small positive: " + i;
        
        case List<?> list when list.isEmpty() -> "Empty list";
        case List<?> list -> "List with " + list.size() + " items";
        
        case null -> "null value";
        default -> "Unknown type";
    };
}

// Real-world REST API example
@PostMapping("/process")
public ResponseEntity<?> process(@RequestBody Object data) {
    return switch (data) {
        case UserRequest r when r.isValid() -> 
            ResponseEntity.ok(userService.create(r));
            
        case UserRequest r -> 
            ResponseEntity.badRequest().body("Invalid user data");
            
        case OrderRequest r when r.getTotalAmount() > 10000 -> 
            ResponseEntity.status(HttpStatus.PAYMENT_REQUIRED)
                         .body("Amount exceeds limit");
                         
        case OrderRequest r -> 
            ResponseEntity.ok(orderService.create(r));
            
        case null -> 
            ResponseEntity.badRequest().body("Request body required");
            
        default -> 
            ResponseEntity.badRequest().body("Unsupported request type");
    };
}
```

### 5.3 Record Patterns (Standard in Java 21)

```java
// Define records
record Point(int x, int y) {}
record Circle(Point center, int radius) {}
record Rectangle(Point topLeft, Point bottomRight) {}
record ColoredShape(Shape shape, String color) {}

sealed interface Shape permits Circle, Rectangle {}

// Deconstruct records in pattern matching
public double calculateArea(Shape shape) {
    return switch (shape) {
        case Circle(Point(int x, int y), int r) -> 
            Math.PI * r * r;
            
        case Rectangle(Point(int x1, int y1), Point(int x2, int y2)) -> 
            Math.abs(x2 - x1) * Math.abs(y2 - y1);
    };
}

// Nested patterns
public String describeShape(Object obj) {
    return switch (obj) {
        case ColoredShape(Circle(Point(var x, var y), var r), var color) ->
            String.format("%s circle at (%d,%d) with radius %d", color, x, y, r);
            
        case ColoredShape(Rectangle(var topLeft, var bottomRight), var color) ->
            String.format("%s rectangle from %s to %s", color, topLeft, bottomRight);
            
        case Circle c -> "Uncolored circle";
        case Rectangle r -> "Uncolored rectangle";
        
        default -> "Unknown shape";
    };
}

// REST API validation example
record CreateUserRequest(String email, String name, Integer age) {
    public boolean isValid() {
        return email != null && name != null && age != null;
    }
}

@PostMapping("/users")
public ResponseEntity<?> createUser(@RequestBody Object request) {
    return switch (request) {
        case CreateUserRequest(var email, var name, var age) 
            when email.contains("@") && age >= 18 ->
            ResponseEntity.ok(userService.create(email, name, age));
            
        case CreateUserRequest(var email, _, var age) 
            when !email.contains("@") ->
            ResponseEntity.badRequest().body("Invalid email");
            
        case CreateUserRequest(_, _, var age) 
            when age < 18 ->
            ResponseEntity.badRequest().body("Must be 18+");
            
        case CreateUserRequest _ ->
            ResponseEntity.badRequest().body("Invalid request");
            
        default ->
            ResponseEntity.badRequest().body("Invalid request format");
    };
}

// Database entity mapping example
record UserEntity(Long id, String email, String name, LocalDateTime createdAt) {}

public Optional<UserDTO> mapToDTO(Object entity) {
    return switch (entity) {
        case UserEntity(var id, var email, var name, var createdAt) 
            when id != null ->
            Optional.of(new UserDTO(id, email, name, createdAt));
            
        case UserEntity _ ->
            Optional.empty();
            
        default ->
            Optional.empty();
    };
}
```

### 5.4 Sequenced Collections (Standard in Java 21)

New interfaces and methods for ordered collections:

```java
// New methods available on List, Deque, LinkedHashSet, LinkedHashMap

List<String> list = new ArrayList<>(List.of("a", "b", "c", "d"));

// Add/remove at both ends
list.addFirst("first");           // ["first", "a", "b", "c", "d"]
list.addLast("last");             // ["first", "a", "b", "c", "d", "last"]

String first = list.getFirst();   // "first"
String last = list.getLast();     // "last"

list.removeFirst();               // ["a", "b", "c", "d", "last"]
list.removeLast();                // ["a", "b", "c", "d"]

// Reversed views (efficient - no copying!)
List<String> reversed = list.reversed();  // ["d", "c", "b", "a"]
reversed.addFirst("x");                   // Also affects original!

// Works with LinkedHashSet
LinkedHashSet<String> set = new LinkedHashSet<>();
set.addFirst("first");
set.addLast("last");
String firstInSet = set.getFirst();
Set<String> reversedSet = set.reversed();

// Works with LinkedHashMap
LinkedHashMap<String, Integer> map = new LinkedHashMap<>();
map.putFirst("first", 1);
map.putLast("last", 100);

Entry<String, Integer> firstEntry = map.firstEntry();  // first=1
Entry<String, Integer> lastEntry = map.lastEntry();    // last=100

Map<String, Integer> reversedMap = map.reversed();

// Real-world example - LRU Cache
public class LRUCache<K, V> {
    private final LinkedHashMap<K, V> cache;
    private final int maxSize;
    
    public LRUCache(int maxSize) {
        this.maxSize = maxSize;
        this.cache = new LinkedHashMap<>();
    }
    
    public void put(K key, V value) {
        // Remove oldest if at capacity
        if (cache.size() >= maxSize) {
            K oldestKey = cache.firstEntry().getKey();  // NEW METHOD
            cache.remove(oldestKey);
        }
        cache.putLast(key, value);  // NEW METHOD - add to end
    }
    
    public V get(K key) {
        V value = cache.remove(key);
        if (value != null) {
            cache.putLast(key, value);  // Move to end (most recent)
        }
        return value;
    }
}

// Queue operations with List
public class TaskQueue {
    private final List<Task> tasks = new ArrayList<>();
    
    public void enqueue(Task task) {
        tasks.addLast(task);  // Add to end
    }
    
    public Task dequeue() {
        return tasks.removeFirst();  // Remove from start
    }
    
    public Task peekNext() {
        return tasks.getFirst();  // Look at next without removing
    }
    
    public List<Task> getReversed() {
        return tasks.reversed();  // Efficient reversed view
    }
}
```

### 5.5 String Templates (Preview in Java 21)

**Note**: This is a preview feature in Java 21. Enable with `--enable-preview`.

```java
// Enable preview features in Maven
<maven.compiler.enablePreview>true</maven.compiler.enablePreview>

// Traditional string concatenation
String name = "John";
int age = 30;
String message = "Name: " + name + ", Age: " + age;

// With String.format
String message = String.format("Name: %s, Age: %d", name, age);

// With String Templates (Java 21 Preview)
String message = STR."Name: \{name}, Age: \{age}";

// Complex expressions
String json = STR."""
    {
        "name": "\{user.getName().toUpperCase()}",
        "age": \{user.getAge()},
        "status": "\{user.isActive() ? "active" : "inactive"}",
        "balance": \{user.getBalance() * 1.1}
    }
    """;

// SQL generation
String sql = STR."""
    SELECT * FROM users 
    WHERE email = '\{email}' 
    AND status = '\{status}'
    ORDER BY created_at DESC
    LIMIT \{limit}
    """;

// HTML generation
String html = STR."""
    <div class="user-card">
        <h2>\{user.getName()}</h2>
        <p>Email: \{user.getEmail()}</p>
        <p>Member since: \{user.getCreatedAt().getYear()}</p>
    </div>
    """;
```

**To use preview features**:
```xml
<!-- Maven -->
<properties>
    <maven.compiler.enablePreview>true</maven.compiler.enablePreview>
</properties>

<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <configuration>
        <argLine>--enable-preview</argLine>
    </configuration>
</plugin>
```

```gradle
// Gradle
tasks.withType(JavaCompile) {
    options.compilerArgs += ['--enable-preview']
}

tasks.withType(Test) {
    jvmArgs += ['--enable-preview']
}
```

### 5.6 Scoped Values (Preview in Java 21)

Better alternative to ThreadLocal:

```java
// Traditional ThreadLocal (problems with thread pools)
public class UserContext {
    private static final ThreadLocal<User> CURRENT_USER = new ThreadLocal<>();
    
    public static void setCurrentUser(User user) {
        CURRENT_USER.set(user);
    }
    
    public static User getCurrentUser() {
        return CURRENT_USER.get();
    }
    
    public static void clear() {
        CURRENT_USER.remove();  // Easy to forget!
    }
}

// Java 21 Scoped Values (better)
public class UserContext {
    public static final ScopedValue<User> CURRENT_USER = ScopedValue.newInstance();
    public static final ScopedValue<String> REQUEST_ID = ScopedValue.newInstance();
}

// Usage
public void handleRequest(User user, String requestId) {
    ScopedValue.runWhere(UserContext.CURRENT_USER, user, () -> {
        ScopedValue.runWhere(UserContext.REQUEST_ID, requestId, () -> {
            // CURRENT_USER and REQUEST_ID available in this scope
            processRequest();
            // Automatically cleaned up when scope exits
        });
    });
}

// Access in nested methods
public void processRequest() {
    User user = UserContext.CURRENT_USER.get();
    String requestId = UserContext.REQUEST_ID.get();
    
    log.info("Processing request {} for user {}", requestId, user.getEmail());
    
    businessLogic();  // Can also access scoped values
}

// Spring Boot integration
@Component
public class ScopedValueFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        String requestId = UUID.randomUUID().toString();
        User user = extractUser(httpRequest);
        
        ScopedValue.runWhere(UserContext.CURRENT_USER, user, () -> {
            ScopedValue.runWhere(UserContext.REQUEST_ID, requestId, () -> {
                try {
                    chain.doFilter(request, response);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        });
    }
}
```

---

## Phase 6: Update Dependencies

### 6.1 Spring Boot

```xml
<!-- Recommended: Spring Boot 3.2+ for full Java 21 support -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.2</version>
</parent>
```

### 6.2 Core Libraries

```xml
<!-- Lombok - Java 21 support -->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.18.30</version>
    <scope>provided</scope>
</dependency>

<!-- MapStruct - Java 21 support -->
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

<!-- Jackson - Latest -->
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.16.1</version>
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
```

### 6.3 Database Drivers

```xml
<!-- PostgreSQL -->
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <version>42.7.1</version>
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
    <version>23.3.0.23.09</version>
</dependency>

<!-- SQL Server -->
<dependency>
    <groupId>com.microsoft.sqlserver</groupId>
    <artifactId>mssql-jdbc</artifactId>
    <version>12.4.2.jre11</version>
</dependency>

<!-- H2 (testing) -->
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <version>2.2.224</version>
    <scope>test</scope>
</dependency>
```

### 6.4 Testing Libraries

```xml
<!-- JUnit 5 -->
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.10.1</version>
    <scope>test</scope>
</dependency>

<!-- Mockito -->
<dependency>
    <groupId>org.mockito</groupId>
    <artifactId>mockito-core</artifactId>
    <version>5.8.0</version>
    <scope>test</scope>
</dependency>

<!-- AssertJ -->
<dependency>
    <groupId>org.assertj</groupId>
    <artifactId>assertj-core</artifactId>
    <version>3.25.1</version>
    <scope>test</scope>
</dependency>

<!-- TestContainers -->
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

### 6.5 Cloud SDKs

```xml
<!-- AWS SDK v2 -->
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>software.amazon.awssdk</groupId>
            <artifactId>bom</artifactId>
            <version>2.21.42</version>
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
            <version>26.28.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<!-- Azure Spring Cloud -->
<dependency>
    <groupId>com.azure.spring</groupId>
    <artifactId>spring-cloud-azure-dependencies</artifactId>
    <version>5.7.0</version>
    <type>pom</type>
    <scope>import</scope>
</dependency>
```

---

## Phase 7: JVM Tuning for Java 21

### 7.1 Generational ZGC (New in Java 21)

Generational ZGC provides dramatically better performance than ZGC in Java 17:

```bash
# Enable Generational ZGC (recommended for Java 21)
java -XX:+UseZGC -XX:+ZGenerational -jar app.jar

# With memory settings
java -XX:+UseZGC \
     -XX:+ZGenerational \
     -Xmx4g \
     -Xms4g \
     -jar app.jar

# For containerized apps
java -XX:+UseZGC \
     -XX:+ZGenerational \
     -XX:+UseContainerSupport \
     -XX:MaxRAMPercentage=75.0 \
     -jar app.jar
```

### 7.2 G1GC (Still Default, Improved in Java 21)

```bash
# G1GC with optimizations
java -XX:+UseG1GC \
     -XX:MaxGCPauseMillis=200 \
     -XX:G1HeapRegionSize=16m \
     -XX:InitiatingHeapOccupancyPercent=45 \
     -XX:G1ReservePercent=10 \
     -Xmx4g \
     -Xms4g \
     -jar app.jar
```

### 7.3 Recommended JVM Flags for Production

```bash
# Complete production-ready configuration
java \
  -XX:+UseZGC \
  -XX:+ZGenerational \
  -XX:+UseContainerSupport \
  -XX:MaxRAMPercentage=75.0 \
  -XX:InitialRAMPercentage=50.0 \
  -XX:+AlwaysPreTouch \
  -XX:+DisableExplicitGC \
  -XX:+UseStringDeduplication \
  -Djava.security.egd=file:/dev/./urandom \
  -Dfile.encoding=UTF-8 \
  -jar app.jar
```

### 7.4 GC Logging (for monitoring)

```bash
# Enable GC logging
java -Xlog:gc*:file=gc.log:time,uptime:filecount=5,filesize=100M \
     -XX:+UseZGC \
     -XX:+ZGenerational \
     -jar app.jar
```

### 7.5 Virtual Thread JVM Options

```bash
# Virtual thread scheduler configuration (usually defaults are fine)
java -Djdk.virtualThreadScheduler.parallelism=100 \
     -Djdk.virtualThreadScheduler.maxPoolSize=256 \
     -jar app.jar
```

---

## Phase 8: Docker Configuration

### 8.1 Dockerfile with Java 21

```dockerfile
# Multi-stage build
FROM eclipse-temurin:21-jdk-jammy AS build

WORKDIR /app

# Copy Maven wrapper and pom.xml
COPY .mvn/ .mvn
COPY mvnw pom.xml ./

# Download dependencies (cached layer)
RUN ./mvnw dependency:go-offline

# Copy source and build
COPY src ./src
RUN ./mvnw clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Create non-root user
RUN groupadd -r spring && useradd -r -g spring spring

# Copy JAR from build stage
COPY --from=build /app/target/*.jar app.jar

# Change ownership
RUN chown spring:spring app.jar

# Switch to non-root user
USER spring:spring

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

# JVM options
ENV JAVA_OPTS="-XX:+UseZGC -XX:+ZGenerational -XX:MaxRAMPercentage=75.0 -XX:+UseContainerSupport"

# Run
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
```

### 8.2 Docker Compose

```yaml
version: '3.9'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    image: myapp:java21
    container_name: myapp
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=production
      - SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/mydb
      - SPRING_DATASOURCE_USERNAME=postgres
      - SPRING_DATASOURCE_PASSWORD=password
      - JAVA_OPTS=-XX:+UseZGC -XX:+ZGenerational -Xmx2g
      - SPRING_THREADS_VIRTUAL_ENABLED=true
    depends_on:
      db:
        condition: service_healthy
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/actuator/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 40s
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    container_name: postgres
    environment:
      - POSTGRES_DB=mydb
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres-data:
```

### 8.3 Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  labels:
    app: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:java21
        ports:
        - containerPort: 8080
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: "production"
        - name: SPRING_THREADS_VIRTUAL_ENABLED
          value: "true"
        - name: JAVA_OPTS
          value: "-XX:+UseZGC -XX:+ZGenerational -XX:MaxRAMPercentage=75.0"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: 8080
          initialDelaySeconds: 45
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: myapp-service
spec:
  selector:
    app: myapp
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: LoadBalancer
```

---

## Phase 9: Spring Boot Configuration for Java 21

### 9.1 Enable Virtual Threads

**application.properties**:
```properties
# Enable virtual threads (Spring Boot 3.2+)
spring.threads.virtual.enabled=true

# Application settings
spring.application.name=my-app
server.port=8080

# Actuator
management.endpoints.web.exposure.include=health,info,metrics,prometheus
management.endpoint.health.show-details=always

# Database (increased pool for virtual threads)
spring.datasource.hikari.maximum-pool-size=50
spring.datasource.hikari.minimum-idle=20
```

**application.yml**:
```yaml
spring:
  application:
    name: my-app
  threads:
    virtual:
      enabled: true
  datasource:
    url: jdbc:postgresql://localhost:5432/mydb
    username: postgres
    password: password
    hikari:
      maximum-pool-size: 50
      minimum-idle: 20
      connection-timeout: 30000

server:
  port: 8080
  shutdown: graceful

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
  metrics:
    tags:
      application: ${spring.application.name}
```

### 9.2 Virtual Thread Configuration Class

```java
@Configuration
public class VirtualThreadConfiguration {
    
    private static final Logger log = LoggerFactory.getLogger(VirtualThreadConfiguration.class);
    
    @Bean
    public TomcatProtocolHandlerCustomizer<?> protocolHandlerVirtualThreadExecutorCustomizer() {
        return protocolHandler -> {
            log.info("Configuring Tomcat to use virtual threads");
            protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        };
    }
    
    @Bean(name = "taskExecutor")
    public AsyncTaskExecutor asyncTaskExecutor() {
        log.info("Configuring async task executor with virtual threads");
        return new TaskExecutorAdapter(Executors.newVirtualThreadPerTaskExecutor());
    }
    
    @Bean
    public AsyncConfigurer asyncConfigurer() {
        return new AsyncConfigurer() {
            @Override
            public Executor getAsyncExecutor() {
                return Executors.newVirtualThreadPerTaskExecutor();
            }
            
            @Override
            public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
                return (ex, method, params) -> 
                    log.error("Async method {} threw exception", method.getName(), ex);
            }
        };
    }
}
```

---

## Phase 10: Testing & Validation

### 10.1 Unit Tests

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

### 10.2 Virtual Thread Tests

```java
@SpringBootTest
class VirtualThreadIntegrationTest {
    
    @Test
    void shouldUseVirtualThreads() throws Exception {
        // Verify virtual threads are being used
        Thread currentThread = Thread.currentThread();
        assertThat(currentThread.isVirtual()).isTrue();
    }
    
    @Test
    void shouldHandleMillionsOfVirtualThreads() throws Exception {
        int taskCount = 100_000;
        AtomicInteger completed = new AtomicInteger(0);
        
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < taskCount; i++) {
                executor.submit(() -> {
                    try {
                        Thread.sleep(Duration.ofMillis(100));
                        completed.incrementAndGet();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
        }
        
        assertThat(completed.get()).isEqualTo(taskCount);
    }
}
```

### 10.3 Performance Benchmarking

```java
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Fork(value = 2, jvmArgs = {"-Xms2G", "-Xmx2G"})
@Warmup(iterations = 3)
@Measurement(iterations = 5)
public class Java21Benchmark {
    
    @Benchmark
    public void platformThreads() throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(200);
        for (int i = 0; i < 10000; i++) {
            executor.submit(() -> {
                try {
                    Thread.sleep(Duration.ofMillis(10));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.MINUTES);
    }
    
    @Benchmark
    public void virtualThreads() throws InterruptedException {
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < 10000; i++) {
                executor.submit(() -> {
                    try {
                        Thread.sleep(Duration.ofMillis(10));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
        }
    }
}
```

### 10.4 Migration Validation Script

```bash
#!/bin/bash
# validate-java21.sh

echo "=== Java 21 Migration Validator ==="

# Check Java version
echo "Checking Java version..."
JAVA_VERSION=$(java -version 2>&1 | grep "version" | awk -F'"' '{print $2}' | cut -d'.' -f1)
if [ "$JAVA_VERSION" != "21" ]; then
    echo "❌ Java 21 required (found: Java $JAVA_VERSION)"
    exit 1
fi
echo "✓ Java 21 detected"

# Check Spring Boot version
echo "Checking Spring Boot version..."
if grep -q "<version>3\.[2-9]" pom.xml || grep -q "<version>3\.1[0-9]" pom.xml; then
    echo "✓ Spring Boot 3.2+ detected"
else
    echo "⚠️  Spring Boot 3.2+ recommended for full Java 21 support"
fi

# Check for virtual thread configuration
echo "Checking virtual thread configuration..."
if grep -rq "spring.threads.virtual.enabled=true" src/main/resources/ || \
   grep -rq "newVirtualThreadPerTaskExecutor" src/; then
    echo "✓ Virtual threads configured"
else
    echo "ℹ️  Virtual threads not configured (optional but recommended)"
fi

# Build test
echo "Building project..."
if mvn clean compile -q; then
    echo "✓ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# Run tests
echo "Running tests..."
if mvn test -q; then
    echo "✓ All tests passed"
else
    echo "❌ Tests failed"
    exit 1
fi

# Check for pattern matching usage
echo "Checking for Java 21 features..."
if grep -rq "case.*when" src/ || grep -rq "case.*->" src/; then
    echo "✓ Pattern matching in use"
else
    echo "ℹ️  Consider using pattern matching for cleaner code"
fi

echo ""
echo "=== Summary ==="
echo "✓ Java 21 migration successful"
echo "✓ Application ready for deployment"
echo ""
echo "Recommendations:"
echo "  - Enable virtual threads if not already done"
echo "  - Use pattern matching for switch statements"
echo "  - Consider Generational ZGC for GC"
echo "  - Review sequenced collections usage"
```

---

## Phase 11: APM and Monitoring Updates

### 11.1 APM Agent Compatibility

Ensure your APM agents support Java 21:

- **New Relic**: Agent 8.7+ for Java 21
- **Datadog**: Agent 1.21+ for Java 21
- **Dynatrace**: OneAgent 1.261+ for Java 21
- **AppDynamics**: Agent 23.1+ for Java 21
- **Elastic APM**: Agent 1.42+ for Java 21

### 11.2 New Relic Configuration

```yaml
# newrelic.yml
common: &default_settings
  license_key: '<%= ENV["NEW_RELIC_LICENSE_KEY"] %>'
  app_name: My Application (Java 21)
  
  # Enable virtual thread monitoring
  class_transformer:
    com.newrelic.instrumentation.virtual-threads:
      enabled: true

production:
  <<: *default_settings
```

### 11.3 Prometheus Metrics

```properties
# application.properties
management.metrics.export.prometheus.enabled=true
management.metrics.tags.java_version=21
management.metrics.tags.gc_type=ZGC-Generational
```

### 11.4 Custom Metrics for Virtual Threads

```java
@Component
public class VirtualThreadMetrics {
    
    private final MeterRegistry meterRegistry;
    
    public VirtualThreadMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        
        // Monitor virtual threads
        Gauge.builder("jvm.threads.virtual", this, VirtualThreadMetrics::getVirtualThreadCount)
            .description("Number of virtual threads")
            .register(meterRegistry);
    }
    
    private long getVirtualThreadCount() {
        return Thread.getAllStackTraces().keySet().stream()
            .filter(Thread::isVirtual)
            .count();
    }
}
```

---

## Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| Build fails with unrecognized syntax | Language level not set to 21 | Update Maven/Gradle to Java 21 |
| Virtual threads not working | Spring Boot < 3.2 | Upgrade to Spring Boot 3.2+ |
| Pattern matching errors | Preview features needed | Update to Java 21 (no preview needed) |
| Performance regression | Wrong GC configuration | Use `-XX:+UseZGC -XX:+ZGenerational` |
| Tests failing | Surefire plugin outdated | Update to maven-surefire-plugin 3.1.2+ |
| Docker build fails | Wrong base image | Use `eclipse-temurin:21-jdk` |
| APM agent errors | Agent doesn't support Java 21 | Update APM agent to latest version |
| Connection pool exhausted | Not enough connections for virtual threads | Increase HikariCP pool size to 50+ |

---

## Complete Migration Checklist

### Pre-Migration
- [ ] Verified Spring Boot 3.2+ compatibility
- [ ] Checked all dependencies support Java 21
- [ ] Created rollback plan
- [ ] Documented current performance metrics

### Configuration Updates
- [ ] Updated `pom.xml`/`build.gradle` to Java 21
- [ ] Updated Maven/Gradle plugins
- [ ] Configured build tools for Java 21

### Development Environment
- [ ] Installed JDK 21 LTS
- [ ] Updated IDE (IntelliJ 2023.2+, Eclipse 2023-09+)
- [ ] Configured IDE project SDK to Java 21

### CI/CD Updates
- [ ] Updated GitHub Actions to Java 21
- [ ] Updated Jenkins pipeline to Java 21
- [ ] Updated GitLab CI to Java 21
- [ ] Updated Docker base images to Java 21

### Spring Boot Configuration
- [ ] Upgraded to Spring Boot 3.2+
- [ ] Enabled virtual threads (`spring.threads.virtual.enabled=true`)
- [ ] Configured virtual thread executor beans
- [ ] Increased database connection pool size

### Code Modernization
- [ ] Refactored to pattern matching for switch
- [ ] Applied record patterns
- [ ] Used sequenced collections APIs
- [ ] Implemented virtual threads for I/O operations
- [ ] Replaced ThreadLocal with ScopedValues (if applicable)

### Dependencies
- [ ] Updated Lombok to 1.18.30+
- [ ] Updated MapStruct to 1.5.5+
- [ ] Updated Jackson to 2.16+
- [ ] Updated database drivers
- [ ] Updated testing libraries (JUnit 5.10+, Mockito 5.8+)
- [ ] Updated cloud SDKs

### JVM Optimization
- [ ] Configured Generational ZGC (`-XX:+UseZGC -XX:+ZGenerational`)
- [ ] Set container support flags
- [ ] Configured GC logging
- [ ] Optimized memory settings

### Docker & Kubernetes
- [ ] Updated Dockerfile to `eclipse-temurin:21`
- [ ] Configured JVM options in container
- [ ] Updated Docker Compose
- [ ] Updated Kubernetes manifests
- [ ] Tested container builds

### Testing
- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Virtual thread tests created
- [ ] Performance benchmarks completed
- [ ] Load testing performed

### Monitoring
- [ ] Updated APM agents to Java 21 compatible versions
- [ ] Configured virtual thread metrics
- [ ] Set up alerts for Java 21 specific metrics
- [ ] Verified distributed tracing works

### Documentation
- [ ] Updated README with Java 21 requirements
- [ ] Documented virtual thread usage
- [ ] Updated deployment documentation
- [ ] Created migration notes

### Deployment
- [ ] Deployed to dev environment
- [ ] Monitored dev for 3-5 days
- [ ] Deployed to staging/QA
- [ ] Full regression testing completed
- [ ] Deployed to production (canary)
- [ ] Monitored production for 48-72 hours
- [ ] Full production rollout

---

## Timeline Estimate

| Application Size | Estimated Duration |
|-----------------|-------------------|
| Small (< 50k LOC) | 3-5 days |
| Medium (50k-200k LOC) | 1-2 weeks |
| Large (200k-500k LOC) | 2-4 weeks |
| Enterprise (> 500k LOC) | 4-6 weeks |

---

## Key Benefits Summary

### Performance Improvements
✅ **Virtual Threads**: 10-100x scalability for I/O-bound workloads  
✅ **Generational ZGC**: 50%+ reduction in GC pause times  
✅ **Overall**: 10-15% general performance improvement  

### Developer Experience
✅ **Pattern Matching**: Cleaner, more readable code  
✅ **Record Patterns**: Elegant data extraction  
✅ **Sequenced Collections**: Better list/set operations  
✅ **Less Boilerplate**: More concise code  

### Production Benefits
✅ **LTS Support**: Until September 2031 (vs 2029 for Java 17)  
✅ **Stability**: Production-ready features only  
✅ **Security**: Latest security patches and improvements  
✅ **Future-Proof**: Modern foundation for years to come  

---

## Final Recommendations

### Why Java 21 Over Java 25?

| Factor | Java 21 LTS | Java 25 (non-LTS) |
|--------|-------------|-------------------|
| **Support Duration** | 8 years (2031) | 6 months (Mar 2026) |
| **Stability** | Production-proven | Bleeding edge |
| **Features** | All production-ready | Some preview features |
| **Recommendation** | ✅ **Use for production** | ⚠️ Experimentation only |

### Adoption Strategy

**For Production Applications**:
1. ✅ Migrate to Java 21 LTS
2. ✅ Enable virtual threads immediately (biggest win)
3. ✅ Use Generational ZGC
4. ✅ Adopt pattern matching gradually
5. ✅ Stay on Java 21 until Java 25 LTS (Sept 2026)

**Quick Wins**:
1. **Enable virtual threads** - 1 line config, massive scalability
2. **Use Generational ZGC** - 1 JVM flag, better GC performance
3. **Pattern matching** - Cleaner switch statements
4. **Sequenced collections** - Better APIs for ordered data

### Success Metrics

Monitor these after migration:
- Throughput (requests/second) - Should increase 20-50%
- Response time (p95, p99) - Should decrease with virtual threads
- GC pause time - Should decrease with Gen ZGC
- Memory usage - Monitor for any regressions
- Error rates - Should remain stable

---

*Your application is now running on Java 21 LTS with production-ready virtual threads, pattern matching, and Generational ZGC. You're set until 2031!*

**Good luck with your migration!** 

