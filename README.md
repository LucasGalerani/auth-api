<div align="center">

<img src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/spring/spring-original.svg" alt="Spring" title="Java" width="200px" style="margin: 20px" />

# 🌱 Spring Security + JWT 🔐  
</div>

---

<p align="center">
  <img src="https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=openjdk&logoColor=white" />
  <img src="https://img.shields.io/badge/spring-%236DB33F.svg?style=for-the-badge&logo=spring&logoColor=white" />
  <img src="https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens" />
</p>

---

## 📌 Sobre o Projeto

Este repositório foi criado com o objetivo de **dominar o uso do Spring Security** com autenticação via **JWT** (JSON Web Token), garantindo um sistema de autenticação robusto e seguro. O projeto foi inspirado na vídeo-aula da [**Fernanda Kipper**](https://github.com/Fernanda-Kipper/auth-api/blob/master/README.md) e utiliza as seguintes tecnologias:

> 🧩 Java · Spring Boot · Spring Security · JWT · PostgreSQL

---

## 🚀 Instalação

### 🔧 Pré-requisitos
- Java 17+
- Maven 3.8+
- PostgreSQL

### 📥 Clone o Repositório
```bash
git clone https://github.com/LucasGalerani/auth-api.git
cd auth-api
````

### 📦 Instale as Dependências

```bash
mvn clean install
```

### 🛢️ Configure o Banco de Dados

* Instale e configure o [PostgreSQL](https://www.postgresql.org/)
* Crie um banco de dados (por exemplo: `auth_api`)
* Atualize o arquivo `application.properties` com suas credenciais:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/auth_api
spring.datasource.username=seu_usuario
spring.datasource.password=sua_senha
```

---

## 🧪 Como Usar

### ▶️ Inicie a Aplicação

```bash
mvn spring-boot:run
```

> A API estará disponível em: [http://localhost:8080](http://localhost:8080)

---

## 📡 Endpoints da API

| Método | Rota             | Descrição                             | Acesso      |
| ------ | ---------------- | ------------------------------------- | ----------- |
| GET    | `/product`       | Lista todos os produtos               | Autenticado |
| POST   | `/product`       | Cadastra um novo produto              | ADMIN       |
| POST   | `/auth/login`    | Realiza o login e retorna o token JWT | Público     |
| POST   | `/auth/register` | Registra um novo usuário              | Público     |

---

## 🔐 Autenticação & Autorização

Essa aplicação utiliza **Spring Security** com JWT para autenticação baseada em roles.

### 🛡️ Roles disponíveis:

```bash
USER  -> Usuário comum
ADMIN -> Administrador com permissões elevadas
```

* Para acessar rotas protegidas, envie o token JWT no cabeçalho da requisição:

```
Authorization: Bearer <seu_token_jwt>
```

* Apenas usuários com **role ADMIN** podem acessar rotas administrativas.

---

## 📂 Estrutura de Diretórios

```bash
src/
src/
└── main/
    └── java/
        └── com/
            └── login/
                └── Login/
                    ├── controller/
                    │   ├── AuthenticationController.java
                    │   └── ProductController.java
                    │
                    ├── domain/
                    │   ├── product/
                    │   │   ├── Product.java
                    │   │   ├── ProductRequestDTO.java
                    │   │   └── ProductResponseDTO.java
                    │   │
                    │   └── user/
                    │       ├── AuthenticationDTO.java
                    │       ├── LoginResponseDTO.java
                    │       ├── RegisterDTO.java
                    │       ├── User.java
                    │       └── UserRole.java
                    │
                    ├── infra/
                    │   └── security/
                    │       ├── SecurityConfigurations.java
                    │       └── SecurityFilter.java
                    │
                    ├── repositories/
                    │   ├── ProductRepository.java
                    │   └── UserRepository.java
                    │
                    ├── services/
                    │   ├── AuthorizationService.java
                    │   └── TokenService.java
                    │
                    └── LoginApplication.java
```

## 🤝 Contribuição

Contribuições são muito bem-vindas! Se você quiser sugerir melhorias, abra uma **issue** ou envie um **pull request** 💡✨

---

## 🧑‍💻 Autor

Desenvolvido por **Lucas Galerani**
📧 [lucas1501010@gmail.com](mailto:lucas1501010@gmail.com)
🔗 [LinkedIn](https://www.linkedin.com/in/LucasGalerani)

---

## ⭐ Dê uma estrela

Se você achou útil ou interessante, não esqueça de deixar uma ⭐ no repositório para apoiar!
