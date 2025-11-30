# Hexagonal Architecture Guide

> Team guide for building services following Hexagonal Architecture (Ports & Adapters)

## Table of Contents
- [Core Principle](#core-principle)
- [Project Structure](#project-structure)
- [The 13 Rules](#the-13-rules)
- [Quick Reference](#quick-reference)
- [Common Mistakes](#common-mistakes)
- [Examples](#examples)

---

## Core Principle

**The business logic (core) is independent. It doesn't know about databases, frameworks, or external services.**

```
Primary Adapters → Input Ports → Core → Output Ports ← Secondary Adapters
     (HTTP)                                                  (Postgres)
```

---

## Project Structure

```
services/{service-name}/
├── core/
│   ├── domain/              # Business entities & value objects
│   ├── usecases/            # Business logic orchestration
│   └── ports/
│       ├── input/           # What others can call (interfaces)
│       └── output/          # What core needs (interfaces)
│
└── adapters/
    ├── primary/             # Who calls core (HTTP, gRPC, CLI)
    │   ├── http/
    │   ├── grpc/
    │   └── cli/
    │
    └── secondary/           # What core calls (DB, Email, APIs)
        ├── repository/
        ├── email/
        ├── storage/
        └── oauth/
```

---

## The 13 Rules

### Rule 1: The Hexagon (Core)
**Location:** `services/{service-name}/core/`

#### ✅ What goes in core:
- Business entities (User, Order, Product)
- Business rules (password must be 8+ chars)
- Use cases (RegisterUser, PlaceOrder)
- Interfaces (ports) that define what core needs
- Domain errors (ErrUserNotFound, ErrInvalidEmail)

#### ❌ What NEVER goes in core:
- Database code (no GORM, no SQL)
- HTTP handlers (no Gin, no routing)
- External libraries (no SMTP, no AWS SDK)
- Framework imports (except standard library)
- Configuration loading

```
core/
├── domain/           # Entities and value objects
├── usecases/         # Business logic
└── ports/            # Interfaces
    ├── input/        # What others can call
    └── output/       # What core needs
```

---

### Rule 2: Ports (Interfaces)
**Location:** `services/{service-name}/core/ports/`

#### Input Ports (Primary)
What the outside world can call. Implemented by core use cases, called by HTTP/gRPC/CLI.

```go
// core/ports/input/auth_service.go
package input

type AuthService interface {
    Register(email, password string) error
    Login(email, password string) (string, error)
}
```

#### Output Ports (Secondary)
What core needs from outside. Implemented by adapters, called by core.

```go
// core/ports/output/user_repository.go
package output

import "yourapp/core/domain"

type UserRepository interface {
    Save(user *domain.User) error
    FindByEmail(email string) (*domain.User, error)
}
```

#### Rules:
- ✅ Ports are ALWAYS interfaces
- ✅ Name by behavior, not technology (EmailSender, not SMTPSender)
- ✅ Keep ports small and focused
- ✅ Return domain types, not database types

---

### Rule 3: Primary Adapters (Driving Side)
**Location:** `services/{service-name}/adapters/primary/`

Things that DRIVE your application (call your core): HTTP, gRPC, CLI, message consumers.

```
adapters/primary/
├── http/
│   ├── handlers/      # HTTP handlers
│   ├── middleware/    # HTTP middleware
│   ├── dto/           # Request/response structs
│   ├── router.go
│   └── server.go
├── grpc/
└── cli/
```

#### Example:
```go
// adapters/primary/http/handlers/auth_handler.go
package handlers

import (
    "github.com/gin-gonic/gin"
    "yourapp/core/ports/input"
)

type AuthHandler struct {
    authService input.AuthService  // Input port
}

func NewAuthHandler(authService input.AuthService) *AuthHandler {
    return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(c *gin.Context) {
    var req RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Call core through port
    err := h.authService.Register(req.Email, req.Password)
    if err != nil {
        c.JSON(mapError(err))
        return
    }

    c.JSON(201, gin.H{"message": "success"})
}
```

#### Rules:
- ✅ Convert external format → domain format
- ✅ Call core through input ports
- ✅ Handle HTTP/gRPC/CLI specific concerns here
- ✅ Map domain errors to HTTP status codes

---

### Rule 4: Secondary Adapters (Driven Side)
**Location:** `services/{service-name}/adapters/secondary/`

Things that are DRIVEN by core: databases, email services, external APIs.

```
adapters/secondary/
├── repository/
│   ├── postgres/
│   │   ├── user_repository.go
│   │   ├── models.go              # DB models (separate from domain)
│   │   └── mapper.go              # Domain ↔ DB conversion
│   ├── redis/
│   └── inmemory/                  # For testing
├── email/
│   ├── smtp/
│   └── sendgrid/
├── storage/
│   ├── s3/
│   └── local/
└── oauth/
    └── google/
```

#### Example:
```go
// adapters/secondary/repository/postgres/user_repository.go
package postgres

import (
    "gorm.io/gorm"
    "yourapp/core/domain"
    "yourapp/core/ports/output"
)

type UserRepository struct {
    db *gorm.DB
}

func NewUserRepository(db *gorm.DB) output.UserRepository {
    return &UserRepository{db: db}
}

// Implements output.UserRepository
func (r *UserRepository) Save(user *domain.User) error {
    dbModel := r.toDBModel(user)  // Map domain → DB
    return r.db.Create(dbModel).Error
}

func (r *UserRepository) FindByEmail(email string) (*domain.User, error) {
    var dbModel UserModel
    err := r.db.Where("email = ?", email).First(&dbModel).Error
    if err != nil {
        return nil, err
    }
    return r.toDomainModel(&dbModel), nil
}

// DB model (NOT domain model)
type UserModel struct {
    ID        uint   `gorm:"primaryKey"`
    UUID      string `gorm:"type:uuid;uniqueIndex"`
    Email     string `gorm:"uniqueIndex"`
    Password  string
    CreatedAt time.Time
}

// Mappers
func (r *UserRepository) toDBModel(u *domain.User) *UserModel {
    return &UserModel{
        UUID:     u.ID().String(),
        Email:    u.Email(),
        Password: u.PasswordHash(),
    }
}

func (r *UserRepository) toDomainModel(m *UserModel) *domain.User {
    // Reconstruct domain object from DB data
    return domain.ReconstructUser(
        uuid.MustParse(m.UUID),
        m.Email,
        m.Password,
    )
}
```

#### Rules:
- ✅ Implement output ports from core
- ✅ Convert domain types → external format (DB, API)
- ✅ Handle all technology-specific code here
- ✅ Never expose implementation details to core

---

### Rule 5: Dependency Direction
**THE GOLDEN RULE**

```
Primary Adapters → Input Ports → Core → Output Ports ← Secondary Adapters
```

#### What this means:
- ✅ Core imports NOTHING from adapters
- ✅ Adapters import from core (domain, ports)
- ✅ Primary adapters call input ports
- ✅ Core calls output ports (implemented by secondary adapters)

#### Check yourself:
- ❌ If core imports "gorm" → WRONG
- ❌ If core imports "gin" → WRONG
- ❌ If core imports adapter package → WRONG
- ✅ If adapter imports core/domain → CORRECT
- ✅ If adapter imports core/ports → CORRECT

---

### Rule 6: Wiring (Dependency Injection)
**Location:** `cmd/{service-name}/main.go`

```go
package main

import (
    "yourapp/adapters/primary/http/handlers"
    "yourapp/adapters/secondary/repository/postgres"
    "yourapp/adapters/secondary/email/smtp"
    "yourapp/core/usecases"
)

func main() {
    // 1. Load config
    cfg := loadConfig()

    // 2. Create secondary adapters (what core needs)
    db := connectDB(cfg.Database)
    userRepo := postgres.NewUserRepository(db)
    emailSender := smtp.NewEmailSender(cfg.SMTP)
    hasher := bcrypt.NewHasher()

    // 3. Create core use cases (inject dependencies)
    registerUseCase := usecases.NewRegisterUser(
        userRepo,      // output port
        emailSender,   // output port
        hasher,        // output port
    )

    loginUseCase := usecases.NewLogin(userRepo, hasher)

    // 4. Create primary adapters (who calls core)
    authHandler := handlers.NewAuthHandler(
        registerUseCase,  // input port
        loginUseCase,     // input port
    )

    // 5. Start server
    router := setupRouter(authHandler)
    router.Run(":8080")
}
```

#### Rules:
- ✅ Wire in main.go (or bootstrap package)
- ✅ Create adapters from outside-in
- ✅ Pass dependencies through constructors
- ✅ Never use global variables

---

### Rule 7: Domain Entities
**Location:** `services/{service-name}/core/domain/`

```go
// core/domain/user/user.go
package user

import (
    "github.com/google/uuid"
    "time"
)

// Pure business entity - NO struct tags
type User struct {
    id       uuid.UUID
    email    Email       // Value object
    password Password    // Value object
    verified bool
    createdAt time.Time
}

// Factory with validation
func NewUser(email, password string) (*User, error) {
    emailVO, err := NewEmail(email)
    if err != nil {
        return nil, err
    }

    pwdVO, err := NewPassword(password)
    if err != nil {
        return nil, err
    }

    return &User{
        id:       uuid.New(),
        email:    emailVO,
        password: pwdVO,
        verified: false,
        createdAt: time.Now(),
    }, nil
}

// Business method
func (u *User) Verify() error {
    if u.verified {
        return ErrAlreadyVerified
    }
    u.verified = true
    return nil
}

// Controlled access (getters)
func (u *User) ID() uuid.UUID { return u.id }
func (u *User) Email() string { return u.email.String() }
func (u *User) PasswordHash() string { return u.password.Hash() }
func (u *User) IsVerified() bool { return u.verified }

// Reconstruction (for repositories)
func ReconstructUser(id uuid.UUID, email, passwordHash string) *User {
    return &User{
        id:       id,
        email:    MustNewEmail(email),
        password: PasswordFromHash(passwordHash),
        verified: true,
    }
}
```

#### Rules:
- ✅ Pure business logic only
- ✅ No struct tags (no `gorm:`, no `json:`)
- ✅ Use private fields with public getters
- ✅ Business rules in methods
- ✅ Use value objects for validation

---

### Rule 8: Value Objects
**Location:** `services/{service-name}/core/domain/`

Use value objects for: Email, Password, Money, Phone, Address, any validated data.

```go
// core/domain/user/email.go
package user

import (
    "errors"
    "regexp"
    "strings"
)

type Email struct {
    value string
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func NewEmail(email string) (Email, error) {
    email = strings.TrimSpace(strings.ToLower(email))

    if !emailRegex.MatchString(email) {
        return Email{}, ErrInvalidEmail
    }

    return Email{value: email}, nil
}

func MustNewEmail(email string) Email {
    e, _ := NewEmail(email)
    return e
}

func (e Email) String() string {
    return e.value
}

func (e Email) Equals(other Email) bool {
    return e.value == other.value
}
```

```go
// core/domain/user/password.go
package user

import (
    "errors"
    "golang.org/x/crypto/bcrypt"
)

type Password struct {
    hash string
}

func NewPassword(plaintext string) (Password, error) {
    // Business rules
    if len(plaintext) < 8 {
        return Password{}, errors.New("password must be at least 8 characters")
    }
    if !hasUpperCase(plaintext) || !hasLowerCase(plaintext) || !hasDigit(plaintext) {
        return Password{}, errors.New("password must contain upper, lower, and digit")
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
    if err != nil {
        return Password{}, err
    }

    return Password{hash: string(hash)}, nil
}

func PasswordFromHash(hash string) Password {
    return Password{hash: hash}
}

func (p Password) Matches(plaintext string) bool {
    return bcrypt.CompareHashAndPassword([]byte(p.hash), []byte(plaintext)) == nil
}

func (p Password) Hash() string {
    return p.hash
}
```

#### Rules:
- ✅ Immutable (no setters)
- ✅ Validate in constructor
- ✅ Can't create invalid value objects
- ✅ Business rules enforced by type system

---

### Rule 9: Use Cases
**Location:** `services/{service-name}/core/usecases/`

One file per use case:
```
usecases/
├── register_user.go
├── verify_email.go
├── login.go
├── forgot_password.go
└── reset_password.go
```

#### Example:
```go
// core/usecases/register_user.go
package usecases

import (
    "yourapp/core/domain/user"
    "yourapp/core/ports/output"
)

type RegisterUser struct {
    userRepo    output.UserRepository
    emailSender output.EmailSender
    hasher      output.PasswordHasher
}

func NewRegisterUser(
    userRepo output.UserRepository,
    emailSender output.EmailSender,
    hasher output.PasswordHasher,
) *RegisterUser {
    return &RegisterUser{
        userRepo:    userRepo,
        emailSender: emailSender,
        hasher:      hasher,
    }
}

func (uc *RegisterUser) Execute(email, password string) error {
    // 1. Check if user exists
    _, err := uc.userRepo.FindByEmail(email)
    if err == nil {
        return user.ErrUserAlreadyExists
    }

    // 2. Create user (domain validation happens here)
    newUser, err := user.NewUser(email, password)
    if err != nil {
        return err
    }

    // 3. Save to database
    if err := uc.userRepo.Save(newUser); err != nil {
        return err
    }

    // 4. Send verification email
    token := generateToken(newUser.ID())
    if err := uc.emailSender.SendVerification(newUser.Email(), token); err != nil {
        // Log but don't fail registration
        log.Error("failed to send email", err)
    }

    return nil
}
```

#### Rules:
- ✅ One use case = one business operation
- ✅ Orchestrate domain objects
- ✅ Call multiple ports if needed
- ✅ Handle transactions here
- ✅ Return domain errors

---

### Rule 10: Error Handling

```go
// core/domain/user/errors.go
package user

import "errors"

var (
    ErrUserNotFound      = errors.New("user not found")
    ErrUserAlreadyExists = errors.New("user already exists")
    ErrInvalidEmail      = errors.New("invalid email format")
    ErrWeakPassword      = errors.New("password too weak")
    ErrEmailNotVerified  = errors.New("email not verified")
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrAlreadyVerified   = errors.New("already verified")
)
```

Map to HTTP in adapter:
```go
// adapters/primary/http/handlers/errors.go
package handlers

import "github.com/gin-gonic/gin"
import "yourapp/core/domain/user"

func mapError(err error) (int, gin.H) {
    switch err {
    case user.ErrUserNotFound:
        return 404, gin.H{"error": "user not found"}
    case user.ErrUserAlreadyExists:
        return 409, gin.H{"error": "user already exists"}
    case user.ErrInvalidEmail, user.ErrWeakPassword:
        return 400, gin.H{"error": err.Error()}
    case user.ErrEmailNotVerified:
        return 403, gin.H{"error": "email not verified"}
    case user.ErrInvalidCredentials:
        return 401, gin.H{"error": "invalid credentials"}
    default:
        return 500, gin.H{"error": "internal server error"}
    }
}
```

#### Rules:
- ✅ Define errors in domain
- ✅ Don't expose internal details
- ✅ Map to status codes in adapter
- ✅ Log full error, return sanitized version

---

### Rule 11: Testing Strategy

```
# Unit tests (core) - No external dependencies
core/domain/user/user_test.go
core/domain/user/email_test.go
core/usecases/register_user_test.go

# Integration tests (adapters) - Real database
adapters/secondary/repository/postgres/user_repository_test.go

# E2E tests - Full system
tests/e2e/auth_flow_test.go
```

#### Unit Test Example:
```go
// core/domain/user/user_test.go
package user_test

import (
    "testing"
    "yourapp/core/domain/user"
)

func TestNewUser_ValidData_Success(t *testing.T) {
    u, err := user.NewUser("test@example.com", "Pass1234!")

    if err != nil {
        t.Fatalf("expected no error, got %v", err)
    }

    if u.Email() != "test@example.com" {
        t.Errorf("expected test@example.com, got %s", u.Email())
    }

    if u.IsVerified() {
        t.Error("expected user to be unverified")
    }
}

func TestNewUser_InvalidEmail_Error(t *testing.T) {
    _, err := user.NewUser("invalid-email", "Pass1234!")

    if err != user.ErrInvalidEmail {
        t.Errorf("expected ErrInvalidEmail, got %v", err)
    }
}
```

#### Use Case Test with Mocks:
```go
// core/usecases/register_user_test.go
package usecases_test

import (
    "testing"
    "yourapp/core/usecases"
    "yourapp/core/domain/user"
)

type MockUserRepository struct {
    users map[string]*user.User
}

func (m *MockUserRepository) Save(u *user.User) error {
    m.users[u.Email()] = u
    return nil
}

func (m *MockUserRepository) FindByEmail(email string) (*user.User, error) {
    if u, ok := m.users[email]; ok {
        return u, nil
    }
    return nil, user.ErrUserNotFound
}

func TestRegisterUser_Success(t *testing.T) {
    mockRepo := &MockUserRepository{users: make(map[string]*user.User)}
    mockEmail := &MockEmailSender{}
    mockHasher := &MockHasher{}

    uc := usecases.NewRegisterUser(mockRepo, mockEmail, mockHasher)

    err := uc.Execute("test@example.com", "Pass1234!")

    if err != nil {
        t.Fatalf("expected no error, got %v", err)
    }

    if len(mockRepo.users) != 1 {
        t.Error("expected user to be saved")
    }
}
```

---

### Rule 12: Package Naming

#### ✅ Good names:
- `core/domain/user/`
- `core/domain/order/`
- `core/usecases/`
- `core/ports/input/`
- `core/ports/output/`
- `adapters/primary/http/`
- `adapters/secondary/postgres/`

#### ❌ Bad names:
- `models/` (too generic)
- `handlers/` (missing context)
- `services/` (too generic)
- `utils/` (dumping ground)
- `common/` (unclear purpose)

---

### Rule 13: What Goes in pkg/

`pkg/` is for generic utilities with NO business logic, reusable across ALL services.

#### ✅ Examples:
- Logger interface
- Config loader utilities
- HTTP client wrapper
- Generic error utilities
- Validation helpers

```
pkg/
├── logger/
│   ├── logger.go          # Interface
│   └── zap/
│       └── logger.go      # Implementation
├── config/
│   └── loader.go
├── database/
│   └── postgres/
│       └── connector.go
└── http/
    ├── server.go
    └── client.go
```

#### ❌ NOT in pkg/:
- Domain logic
- Business rules
- Service-specific code
- Use cases

---

## Quick Reference

### Before Committing Checklist

- [ ] Does core import any adapter? (should be NO)
- [ ] Does core import external libraries? (should be NO, except stdlib)
- [ ] Are ports interfaces? (should be YES)
- [ ] Do domain entities have struct tags? (should be NO)
- [ ] Are dependencies injected in main.go? (should be YES)
- [ ] Does each use case do ONE thing? (should be YES)
- [ ] Are errors defined in domain? (should be YES)
- [ ] Do adapters implement ports? (should be YES)

### Dependency Flow
```
HTTP Handler → Use Case → Domain Entity
     ↓            ↓            ↓
   (calls)    (uses port) (pure logic)
     ↓            ↓
  Input Port  Output Port
                  ↓
            Repository (implements port)
                  ↓
              Database
```

### File Organization Pattern
```
When adding feature X:

1. core/domain/x/x.go          - Entity
2. core/domain/x/errors.go     - Domain errors
3. core/ports/output/x_repository.go - Port interface
4. core/usecases/create_x.go   - Use case
5. adapters/secondary/postgres/x_repository.go - Implementation
6. adapters/primary/http/handlers/x_handler.go - HTTP handler
7. cmd/service/main.go         - Wire everything
```

---

## Common Mistakes

### ❌ Mistake 1: HTTP logic in use case
```go
// WRONG
func (uc *RegisterUser) Execute(c *gin.Context) {
    var req Request
    c.BindJSON(&req)
    // ...
}
```

**✅ Fix:**
```go
// Handler (adapter)
func (h *Handler) Register(c *gin.Context) {
    var req Request
    c.BindJSON(&req)
    err := h.useCase.Execute(req.Email, req.Password)
}

// Use case (core)
func (uc *RegisterUser) Execute(email, password string) error {
    // Pure business logic
}
```

---

### ❌ Mistake 2: Domain entity with GORM tags
```go
// WRONG
type User struct {
    ID    uint   `gorm:"primaryKey"`
    Email string `gorm:"uniqueIndex"`
}
```

**✅ Fix:**
```go
// Domain (core/domain/user/user.go)
type User struct {
    id    uuid.UUID
    email Email
}

// DB model (adapters/secondary/postgres/models.go)
type UserModel struct {
    ID    uint   `gorm:"primaryKey"`
    UUID  string `gorm:"type:uuid;uniqueIndex"`
    Email string `gorm:"uniqueIndex"`
}
```

---

### ❌ Mistake 3: Global database variable
```go
// WRONG
var DB *gorm.DB

func init() {
    DB = connectDB()
}
```

**✅ Fix:**
```go
// main.go
func main() {
    db := connectDB()
    userRepo := postgres.NewUserRepository(db)
    // Pass db to wherever needed
}

// Repository
type UserRepository struct {
    db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
    return &UserRepository{db: db}
}
```

---

### ❌ Mistake 4: Business logic in handler
```go
// WRONG
func (h *Handler) Register(c *gin.Context) {
    var req Request
    c.BindJSON(&req)

    // Validation (business rule) in handler
    if len(req.Password) < 8 {
        c.JSON(400, "password too short")
        return
    }

    // Direct DB access
    db.Create(&User{Email: req.Email})
}
```

**✅ Fix:**
```go
// Handler
func (h *Handler) Register(c *gin.Context) {
    var req Request
    c.BindJSON(&req)

    err := h.useCase.Execute(req.Email, req.Password)
    if err != nil {
        c.JSON(mapError(err))
        return
    }
    c.JSON(201, "success")
}

// Use case
func (uc *RegisterUser) Execute(email, password string) error {
    user, err := domain.NewUser(email, password)  // Validation here
    if err != nil {
        return err
    }
    return uc.userRepo.Save(user)  // Through port
}
```

---

### ❌ Mistake 5: Port returning database types
```go
// WRONG
type UserRepository interface {
    FindByEmail(email string) (*gorm.Model, error)
}
```

**✅ Fix:**
```go
// CORRECT
type UserRepository interface {
    FindByEmail(email string) (*domain.User, error)
}
```

---

## Examples

### Complete Feature: User Registration

#### 1. Domain Entity
```go
// core/domain/user/user.go
package user

type User struct {
    id       uuid.UUID
    email    Email
    password Password
    verified bool
}

func NewUser(email, password string) (*User, error) {
    emailVO, err := NewEmail(email)
    if err != nil {
        return nil, err
    }

    pwdVO, err := NewPassword(password)
    if err != nil {
        return nil, err
    }

    return &User{
        id:       uuid.New(),
        email:    emailVO,
        password: pwdVO,
        verified: false,
    }, nil
}

func (u *User) ID() uuid.UUID { return u.id }
func (u *User) Email() string { return u.email.String() }
func (u *User) PasswordHash() string { return u.password.Hash() }
```

#### 2. Output Port
```go
// core/ports/output/user_repository.go
package output

import "yourapp/core/domain/user"

type UserRepository interface {
    Save(user *user.User) error
    FindByEmail(email string) (*user.User, error)
}
```

#### 3. Use Case
```go
// core/usecases/register_user.go
package usecases

import (
    "yourapp/core/domain/user"
    "yourapp/core/ports/output"
)

type RegisterUser struct {
    userRepo output.UserRepository
}

func NewRegisterUser(userRepo output.UserRepository) *RegisterUser {
    return &RegisterUser{userRepo: userRepo}
}

func (uc *RegisterUser) Execute(email, password string) error {
    _, err := uc.userRepo.FindByEmail(email)
    if err == nil {
        return user.ErrUserAlreadyExists
    }

    newUser, err := user.NewUser(email, password)
    if err != nil {
        return err
    }

    return uc.userRepo.Save(newUser)
}
```

#### 4. Secondary Adapter (Repository)
```go
// adapters/secondary/repository/postgres/user_repository.go
package postgres

import (
    "gorm.io/gorm"
    "yourapp/core/domain/user"
    "yourapp/core/ports/output"
)

type UserRepository struct {
    db *gorm.DB
}

func NewUserRepository(db *gorm.DB) output.UserRepository {
    return &UserRepository{db: db}
}

func (r *UserRepository) Save(u *user.User) error {
    model := &UserModel{
        UUID:     u.ID().String(),
        Email:    u.Email(),
        Password: u.PasswordHash(),
    }
    return r.db.Create(model).Error
}

func (r *UserRepository) FindByEmail(email string) (*user.User, error) {
    var model UserModel
    err := r.db.Where("email = ?", email).First(&model).Error
    if err == gorm.ErrRecordNotFound {
        return nil, user.ErrUserNotFound
    }
    if err != nil {
        return nil, err
    }

    return user.ReconstructUser(
        uuid.MustParse(model.UUID),
        model.Email,
        model.Password,
    ), nil
}

type UserModel struct {
    ID       uint   `gorm:"primaryKey"`
    UUID     string `gorm:"type:uuid;uniqueIndex"`
    Email    string `gorm:"uniqueIndex"`
    Password string
}
```

#### 5. Primary Adapter (HTTP Handler)
```go
// adapters/primary/http/handlers/auth_handler.go
package handlers

import (
    "github.com/gin-gonic/gin"
    "yourapp/core/usecases"
)

type AuthHandler struct {
    registerUC *usecases.RegisterUser
}

func NewAuthHandler(registerUC *usecases.RegisterUser) *AuthHandler {
    return &AuthHandler{registerUC: registerUC}
}

type RegisterRequest struct {
    Email    string `json:"email" binding:"required"`
    Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Register(c *gin.Context) {
    var req RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    err := h.registerUC.Execute(req.Email, req.Password)
    if err != nil {
        status, response := mapError(err)
        c.JSON(status, response)
        return
    }

    c.JSON(201, gin.H{"message": "registration successful"})
}
```

#### 6. Wiring
```go
// cmd/iam/main.go
package main

import (
    "yourapp/adapters/primary/http/handlers"
    "yourapp/adapters/secondary/repository/postgres"
    "yourapp/core/usecases"
)

func main() {
    // Secondary adapters
    db := connectDB()
    userRepo := postgres.NewUserRepository(db)

    // Use cases
    registerUC := usecases.NewRegisterUser(userRepo)

    // Primary adapters
    authHandler := handlers.NewAuthHandler(registerUC)

    // Router
    r := gin.Default()
    r.POST("/auth/register", authHandler.Register)
    r.Run(":8080")
}
```

---

## Team Workflow

### Adding New Feature

1. **Start in `core/domain`** - Define entities and value objects
2. **Add to `core/ports`** - Define interfaces needed
3. **Write use case in `core/usecases`** - Orchestrate logic
4. **Implement secondary adapters** - Database, email, etc.
5. **Implement primary adapters** - HTTP handlers
6. **Wire in `cmd/main.go`** - Connect everything
7. **Test** - Unit → Integration → E2E

### Code Review Checklist

- [ ] Core has no external dependencies?
- [ ] Ports are interfaces?
- [ ] Adapters implement ports?
- [ ] Business logic in domain/use cases?
- [ ] No business logic in handlers?
- [ ] Separate domain and DB models?
- [ ] Tests included?
- [ ] Dependencies injected?

---

## Benefits

### ✅ Easy to Test
- Unit test domain without database
- Mock ports in use case tests
- Integration test adapters independently

### ✅ Technology Independence
- Switch from Postgres to MongoDB? Change one adapter
- Switch from REST to gRPC? Add new primary adapter
- Switch from SMTP to SendGrid? Change one adapter

### ✅ Business Logic Protection
- Core is pure Go, no framework coupling
- Business rules can't be accidentally changed
- Clear separation of concerns

### ✅ Team Scalability
- Different teams can work on different adapters
- Clear boundaries and interfaces
- Easy to onboard new developers

---

## Summary

**3 Main Parts:**
1. **Core** - Business logic (pure Go, no dependencies)
2. **Ports** - Interfaces (contracts between core and adapters)
3. **Adapters** - Implementations (technology-specific code)

**Golden Rule:**
Core depends on NOTHING. Everything depends on core.

**Flow:**
```
HTTP Request → Handler (Primary Adapter)
           → Use Case (Core)
           → Repository Port (Core Interface)
           → Repository (Secondary Adapter)
           → Database
```

---

## References

- **Hexagonal Architecture**: Alistair Cockburn
- **Clean Architecture**: Robert C. Martin
- **Domain-Driven Design**: Eric Evans

---

**Last Updated:** 2025-11-30
**Version:** 1.0
