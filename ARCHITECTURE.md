````````# Arquitetura do Código

---

## 📂 Entidades

```java
package com.login.Login.domain.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Table(name = "users")
@Entity(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    private String login;
    private String password;
    @Enumerated(EnumType.STRING)
    private UserRole role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return (this.role == UserRole.ADMIN)
                ? List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
                : List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getUsername() {
        return login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

> Esta entidade representa a tabela `users` no banco de dados, sendo mapeada com a JPA. Além disso, ela implementa a interface `UserDetails`, do Spring Security, permitindo que seja utilizada no controle de autenticação e autorização.

Essa classe sobrepõe os métodos exigidos pelo `UserDetails`, que normalmente controlariam expiração, bloqueio e validade das credenciais. Como o projeto tem foco prático, todos retornam `true`. O método relevante é `getAuthorities()`, que define o papel (ROLE) do usuário com base no enum `UserRole`.

```java
@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
    return (this.role == UserRole.ADMIN)
            ? List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
            : List.of(new SimpleGrantedAuthority("ROLE_USER"));
}
```

Esse método converte o valor do enum `UserRole` para o formato esperado pelo Spring Security (`GrantedAuthority`), utilizando a implementação padrão `SimpleGrantedAuthority`.

---

## 🔍 Repositório

```java
package com.login.Login.repositories;

import com.login.Login.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    UserDetails findByLogin(String login);
}
```

> O `UserRepository` é uma interface que herda de `JpaRepository`, permitindo operações CRUD e busca personalizada pelo campo `login`. Ele é essencial para o processo de autenticação do Spring Security.

---

## 🛡️ Infraestrutura de Segurança (`infra.security`)

```java
package com.login.Login.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

    @Autowired
    SecurityFilter securityFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .sessionManagement(
                        session -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "/products/new").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

> Esta classe define a cadeia de filtros e as regras de segurança da aplicação. Como estamos lidando com uma API stateless (baseada em JWT), o `csrf` é desativado e a sessão é configurada como `STATELESS`.

### 🔐 Autorizando Requisições:

```java
// Permitir login e registro sem autenticação
.requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
.requestMatchers(HttpMethod.POST, "/auth/register").permitAll()

// Apenas ADMIN pode cadastrar novos produtos
.requestMatchers(HttpMethod.POST, "/products/new").hasRole("ADMIN")

// Todas as outras requisições precisam de autenticação
.anyRequest().authenticated()
```

Para validar o JWT antes de autorizar acessos, é adicionado um filtro personalizado com `addFilterBefore()`. Esse filtro é injetado com `@Autowired` e é executado **antes** do `UsernamePasswordAuthenticationFilter`.

### 🤐 Senha e Autenticação:

* `PasswordEncoder`: Define a criptografia das senhas com BCrypt.
* `AuthenticationManager`: Obtém o gerenciador de autenticação do Spring.

Esses dois beans são essenciais para o fluxo de login da aplicação.

---

## 🔑 Controller de Autenticação

```java
package com.login.Login.controller;

import com.login.Login.domain.user.AuthenticationDTO;
import com.login.Login.domain.user.LoginResponseDTO;
import com.login.Login.domain.user.RegisterDTO;
import com.login.Login.domain.user.User;
import com.login.Login.repositories.UserRepository;
import com.login.Login.services.TokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class AuthenticationController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid AuthenticationDTO data) {
        var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());
        var auth = this.authenticationManager.authenticate(usernamePassword);

        var token = tokenService.generateToken((User) auth.getPrincipal());

        return ResponseEntity.ok(new LoginResponseDTO(token));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterDTO data) {
        if (userRepository.findByLogin(data.login()) != null) return ResponseEntity.badRequest().build();

        String encryptedPassword = new BCryptPasswordEncoder().encode(data.password());
        User user = new User(null, data.login(), encryptedPassword, data.role());

        this.userRepository.save(user);

        return ResponseEntity.ok().build();
    }
}
```

> Este controller expõe as rotas de autenticação (`/login`) e cadastro (`/register`). Ambas são essenciais para iniciar o fluxo de segurança da aplicação.

### 📥 Registro de Usuário:

```java
@PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterDTO data) {
    // Verifica se o usuário já existe no banco de dados
        if (userRepository.findByLogin(data.login()) != null) return ResponseEntity.badRequest().build();

    // Criptografa a senha com BCrypt
        String encryptedPassword = new BCryptPasswordEncoder().encode(data.password());
        User user = new User(null, data.login(), encryptedPassword, data.role());

    // Salva o novo usuário no banco
        this.userRepository.save(user);

        return ResponseEntity.ok().build();
    }
```

### 🔐 Login do Usuário:

```java
@PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid AuthenticationDTO data) {
    // Cria objeto de autenticação com login e senha
        var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());

    // Realiza a autenticação
        var auth = this.authenticationManager.authenticate(usernamePassword);

    // Gera o token JWT baseado no usuário autenticado
        var token = tokenService.generateToken((User) auth.getPrincipal());

    // Retorna o token para o cliente
        return ResponseEntity.ok(new LoginResponseDTO(token));
    }
```

> A autenticação é feita com `AuthenticationManager` e, em seguida, um JWT é gerado e retornado como resposta. Esse token será usado nas próximas requisições autenticadas.

---

## 🧱 Filtro de Segurança Personalizado

```java
package com.login.Login.infra.security;

import com.login.Login.repositories.UserRepository;
import com.login.Login.services.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        var token = this.recoveryToken(request);
        if (token != null) {
            var login = tokenService.validateToken(token);
            UserDetails user = userRepository.findByLogin(login);

            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    private String recoveryToken(HttpServletRequest request) {
        var authHeader = request.getHeader("Authorization");
        return (authHeader == null)
                ? null
                : authHeader.replace("Bearer ", "");
    }
}
```

O `SecurityFilter` é um filtro customizado que herda de `OncePerRequestFilter`, garantindo que seja executado uma única vez por requisição. Ele tem como função principal **interceptar todas as requisições HTTP** e validar, caso exista, o token JWT no cabeçalho.

### 🔄 Funcionamento detalhado:

* O método `doFilterInternal()` é o ponto de entrada do filtro:

    * Recupera o token JWT presente no cabeçalho `Authorization` da requisição por meio do método `recoveryToken()`.
    * Caso o token exista, é validado através do `TokenService`.
    * Se for válido, o login contido no token é utilizado para buscar o `UserDetails` no banco.
    * Um objeto `UsernamePasswordAuthenticationToken` é então criado com base nas permissões do usuário e registrado no `SecurityContextHolder`, ativando a autenticação da requisição.
    * A execução do filtro continua normalmente com `filterChain.doFilter()`.

* O método `recoveryToken()`:

    * Extrai o cabeçalho `Authorization` da requisição.
    * Remove o prefixo `"Bearer "` — uma convenção comum em APIs REST com autenticação via JWT — e retorna apenas o token puro.

Essa abordagem garante que **todas as requisições autenticadas com um token válido sejam corretamente identificadas** pelo Spring Security, permitindo o uso pleno do controle de acesso com base em roles e authorities.

---

## 🔐 Service de Tokens

```java
package com.login.Login.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.login.Login.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret.getBytes());
            String token = JWT.create()
                    .withIssuer("auth-api")
                    .withSubject(user.getLogin())
                    .withExpiresAt(genExpirationDate())
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException exception) {
            throw new RuntimeException("JWT creation exception", exception);
        }
    }

    public String validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret.getBytes());
            return JWT.require(algorithm)
                    .withIssuer("auth-api")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException exception) {
            return "";
        }
    }

    private Instant genExpirationDate() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
```

O `TokenService` centraliza as regras de negócio relacionadas à geração e validação de tokens JWT utilizados pela aplicação.

---

### 🔧 Geração de Token

```java
public String generateToken(User user)
```

Este método recebe um objeto `User` e gera um token JWT contendo:

* **Issuer (`withIssuer`)**: `"auth-api"` — identifica quem gerou o token;
* **Subject (`withSubject`)**: o login do usuário — representa o proprietário do token;
* **Expiração (`withExpiresAt`)**: definida para 2 horas após a criação do token.

Utiliza o algoritmo HMAC256 com uma chave secreta (definida via variável de ambiente) para assinar o token de forma segura.

---

### 🗓️ Data de Expiração

```java
private Instant genExpirationDate()
```

Este método retorna um `Instant` correspondente a duas horas à frente do momento atual, usando o fuso horário de Brasília (UTC−3). Isso garante que os tokens expiram automaticamente após esse período.

---

### ✅ Validação de Token

```java
public String validateToken(String token)
```

Esse método:

* Verifica se o token recebido foi assinado corretamente;
* Confirma se ele foi emitido por `"auth-api"`;
* Retorna o `subject` (login) se o token for válido;
* Em caso de falha, retorna uma string vazia.

---

### 🔐 Chave Secreta (Secret Key)

O segredo usado para assinar e verificar tokens é definido no arquivo `application.properties`:

```properties
api.security.token.secret=${JWT_SECRET:my-secret-key}
```

Esse valor é carregado como variável de ambiente (`JWT_SECRET`). Se não estiver definido, usa o valor padrão `"my-secret-key"` — **o que não é recomendado em produção**.

> ⚠️ Nunca exponha sua chave secreta em código-fonte público. Use variáveis de ambiente seguras e, de preferência, ferramentas de gerenciamento de segredos.

---

## 🙏 Agradecimentos Especiais

Este projeto foi construído com base na didática excelente da [**Fernanda Kipper**](https://github.com/Fernanda-Kipper/auth-api), que forneceu o conhecimento inicial para a integração entre Spring Security e JWT. Também agradeço à comunidade de desenvolvedores e ao ecossistema Spring por manter uma documentação tão robusta e acessível.

---

## 🚀 Finalização

Este projeto tem como objetivo consolidar os conhecimentos de autenticação e autorização utilizando **Spring Boot**, **JWT**, e **boas práticas de segurança em APIs REST**. Sinta-se à vontade para explorar, sugerir melhorias, ou contribuir!

> **Feito com 💚 por Lucas Galerani**````````