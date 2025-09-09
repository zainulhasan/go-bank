# 🎓 Go Bank - Complete Beginner's Tutorial & Design Pattern Guide

> **For Beginners**: This comprehensive tutorial assumes you're new to Go and design patterns. Every concept is explained step-by-step with visual diagrams and practical examples.

## 📋 Table of Contents
1. [🌟 What You'll Learn](#what-youll-learn)
2. [📖 Project Overview](#project-overview)
3. [🎯 Core Concepts & Design Patterns](#core-concepts--design-patterns)
4. [🏗️ Architecture Deep Dive](#architecture-deep-dive)
5. [📝 Step-by-Step Implementation Guide](#step-by-step-implementation-guide)
6. [🧪 Testing Strategies](#testing-strategies)
7. [🚀 Deployment & Production](#deployment--production)
8. [🎯 Learning Checkpoints](#learning-checkpoints)

---

## 🌟 What You'll Learn

By the end of this tutorial, you'll master:

### Go Programming Concepts
- **Interfaces** - How to define contracts between components
- **Structs & Methods** - Creating objects and behaviors
- **Error Handling** - Go's unique error handling approach
- **Goroutines & Channels** - Concurrent programming (advanced)
- **Package Organization** - Structuring large Go applications

### Design Patterns (With Visual Diagrams)
- **Clean Architecture** - 4-layer application structure
- **Repository Pattern** - Database abstraction layer
- **Dependency Injection** - Loose coupling between components
- **Service Layer Pattern** - Business logic organization
- **Middleware Pattern** - Request processing pipeline

### Production Skills
- **Database Design** - PostgreSQL with migrations
- **Security Implementation** - JWT, password hashing, validation
- **Configuration Management** - Environment-based configuration
- **Testing Strategies** - Unit tests, mocks, integration tests
- **Docker Containerization** - Production deployment

### Real-World Application Development
- **API Design** - RESTful endpoints with proper HTTP codes
- **Authentication Flow** - Complete login/signup system
- **Transaction Management** - Database ACID properties
- **Error Handling** - Graceful error management
- **Logging & Monitoring** - Production-ready observability

---

## 📖 Project Overview

### What We're Building - A Complete Banking System

We're creating a **real banking application** that handles:

```mermaid
graph TB
    User[User] --> Login[Login System]
    User --> Register[Registration]
    Login --> Dashboard[Banking Dashboard]
    Register --> Dashboard
    Dashboard --> Account[Account Management]
    Dashboard --> Transaction[Transactions]
    Account --> Balance[Check Balance]
    Account --> History[Transaction History]
    Transaction --> Deposit[Deposit Money]
    Transaction --> Withdraw[Withdraw Money]
```

**Core Features We'll Build:**

👤 **User Management**
- User registration with email validation
- Secure password hashing (bcrypt)
- JWT-based authentication system
- User profile management

💰 **Account Operations**
- Automatic account creation on registration
- Unique account number generation
- Real-time balance tracking
- Multi-currency support (USD default)

💸 **Transaction System**
- Deposit money to accounts
- Withdraw money with balance validation
- Complete transaction history
- Audit trail for all operations
- Transaction reference IDs

🔒 **Security Features**
- Password encryption with bcrypt
- JWT token authentication
- Request validation and sanitization
- SQL injection prevention
- Rate limiting (future enhancement)

### Why This Project is Perfect for Learning?

**1. Real-World Complexity**
- Handles money (requires precision)
- User authentication (security critical)
- Data consistency (banking requirements)
- Audit trails (regulatory compliance)

**2. Design Pattern Showcase**
- Every major Go pattern is demonstrated
- Clean separation of concerns
- Testable architecture
- Production-ready structure

**3. Modern Go Practices**
- Latest Go 1.21+ features
- Industry-standard libraries
- Professional project structure
- Docker containerization

### Technology Stack Explained

```mermaid
graph TD
    Client[Web Client/API Client] --> Gin[Gin Web Framework]
    Gin --> JWT[JWT Middleware]
    JWT --> Handler[HTTP Handlers]
    Handler --> Service[Service Layer]
    Service --> Repository[Repository Layer]
    Repository --> PostgreSQL[(PostgreSQL Database)]
    
    Config[Viper Config] --> Service
    Config --> Repository
    
    Docker[Docker Container] --> Gin
    Migrate[golang-migrate] --> PostgreSQL
```

**Backend Technologies:**
- **Go 1.21+**: Modern, fast, concurrent programming language
- **Gin Framework**: High-performance HTTP web framework
- **PostgreSQL 15**: Robust, ACID-compliant relational database
- **JWT**: Stateless authentication tokens
- **bcrypt**: Industry-standard password hashing

**Development Tools:**
- **Viper**: Flexible configuration management
- **golang-migrate**: Database schema versioning
- **testify**: Testing framework with mocks
- **Docker**: Containerization for consistency
- **Docker Compose**: Multi-service orchestration

**Why These Choices?**
- **Go**: Excellent for web services, great concurrency, fast compilation
- **Gin**: Fastest Go web framework, great middleware support
- **PostgreSQL**: ACID compliance crucial for financial data
- **JWT**: Stateless, scalable authentication
- **Docker**: Consistent development and deployment environments

---

## 🎯 Core Concepts & Design Patterns

> **Beginner Note**: Design patterns are proven solutions to common programming problems. Think of them as "recipes" that experienced developers use to solve recurring challenges.

### 1. Clean Architecture Pattern 🏗️

**What is Clean Architecture?**
Clean Architecture is like organizing a house - each room has a specific purpose, and rooms are connected in a logical way.

```mermaid
graph TB
    subgraph "Clean Architecture Layers"
        A[HTTP Layer<br/>Handlers & Middleware] --> B[Service Layer<br/>Business Logic]
        B --> C[Repository Layer<br/>Data Access]
        C --> D[Domain Layer<br/>Business Rules & Entities]
    end
    
    subgraph "External Dependencies"
        E[Database]
        F[External APIs]
        G[File System]
    end
    
    C --> E
    C --> F
    C --> G
    
    style D fill:#e1f5fe
    style C fill:#f3e5f5
    style B fill:#e8f5e8
    style A fill:#fff3e0
```

**Why Clean Architecture?**
- ✅ **Testable**: Each layer can be tested independently
- ✅ **Maintainable**: Changes in one layer don't break others
- ✅ **Flexible**: Easy to swap databases or frameworks
- ✅ **Understandable**: Clear separation of responsibilities

**Real Example in Our Banking App:**

```go
// 🔵 Domain Layer - Core business logic (innermost)
type Account struct {
    ID      int     `json:"id"`
    UserID  int     `json:"user_id"`
    Balance float64 `json:"balance"`
}

// Business rule: Can't withdraw more than balance
func (a *Account) CanWithdraw(amount float64) bool {
    return a.Balance >= amount && amount > 0
}

// 🟣 Repository Layer - Data access contracts
type AccountRepository interface {
    GetByID(id int) (*Account, error)
    UpdateBalance(id int, balance float64) error
}

// 🟢 Service Layer - Business operations
type AccountService struct {
    accountRepo AccountRepository // Depends on interface, not implementation
}

func (s *AccountService) Withdraw(accountID int, amount float64) error {
    // 1. Get account data
    account, err := s.accountRepo.GetByID(accountID)
    if err != nil {
        return fmt.Errorf("failed to get account: %w", err)
    }
    
    // 2. Apply business rule
    if !account.CanWithdraw(amount) {
        return errors.New("insufficient balance")
    }
    
    // 3. Update data
    newBalance := account.Balance - amount
    return s.accountRepo.UpdateBalance(accountID, newBalance)
}

// 🟠 HTTP Layer - Request handling (outermost)
func (h *AccountHandler) Withdraw(c *gin.Context) {
    var req WithdrawRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "invalid request"})
        return
    }
    
    err := h.accountService.Withdraw(req.AccountID, req.Amount)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    c.JSON(200, gin.H{"message": "withdrawal successful"})
}
```

**Layer Dependencies Rule:**
```mermaid
graph LR
    A[Outer Layers] --> B[Inner Layers]
    B -.-> A
    
    note1["✅ Outer can depend on Inner<br/>❌ Inner cannot depend on Outer"]
```

### 2. Repository Pattern 📋

**What is Repository Pattern?**
Imagine you have different ways to store your money - bank account, safe, wallet. The Repository pattern is like having a single "money manager" who knows how to access all these different storage methods, but you don't need to know the details.

```mermaid
graph TB
    Service[Service Layer] --> Repo[Repository Interface]
    Repo --> Impl1[PostgreSQL Implementation]
    Repo --> Impl2[MySQL Implementation]
    Repo --> Impl3[In-Memory Implementation]
    Repo --> Impl4[File Storage Implementation]
    
    style Repo fill:#e3f2fd
    style Service fill:#e8f5e8
```

**Benefits:**
- 🔄 **Swappable**: Change database without changing business logic
- 🧪 **Testable**: Use mock implementations for testing
- 📄 **Consistent**: Same interface for all data operations
- 🔒 **Secure**: Centralized data access control

**Detailed Example:**

```go
// Step 1: Define the contract (interface)
type UserRepository interface {
    Create(user *User) (*User, error)
    GetByID(id int) (*User, error)
    GetByEmail(email string) (*User, error)
    Update(user *User) (*User, error)
    Delete(id int) error
}

// Step 2: PostgreSQL implementation
type postgresUserRepository struct {
    db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) UserRepository {
    return &postgresUserRepository{db: db}
}

func (r *postgresUserRepository) Create(user *User) (*User, error) {
    query := `
        INSERT INTO users (email, password_hash, first_name, last_name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING id, created_at, updated_at`
    
    err := r.db.QueryRow(
        query,
        user.Email,
        user.PasswordHash,
        user.FirstName,
        user.LastName,
    ).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
    
    if err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }
    
    return user, nil
}

func (r *postgresUserRepository) GetByEmail(email string) (*User, error) {
    user := &User{}
    query := `
        SELECT id, email, password_hash, first_name, last_name, created_at, updated_at
        FROM users
        WHERE email = $1`
    
    err := r.db.QueryRow(query, email).Scan(
        &user.ID,
        &user.Email,
        &user.PasswordHash,
        &user.FirstName,
        &user.LastName,
        &user.CreatedAt,
        &user.UpdatedAt,
    )
    
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, errors.New("user not found")
        }
        return nil, fmt.Errorf("failed to get user: %w", err)
    }
    
    return user, nil
}

// Step 3: In-memory implementation (for testing)
type inMemoryUserRepository struct {
    users  map[int]*User
    emails map[string]*User
    nextID int
    mutex  sync.RWMutex
}

func NewInMemoryUserRepository() UserRepository {
    return &inMemoryUserRepository{
        users:  make(map[int]*User),
        emails: make(map[string]*User),
        nextID: 1,
    }
}

func (r *inMemoryUserRepository) Create(user *User) (*User, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()
    
    // Check if email already exists
    if _, exists := r.emails[user.Email]; exists {
        return nil, errors.New("email already exists")
    }
    
    user.ID = r.nextID
    r.nextID++
    user.CreatedAt = time.Now()
    user.UpdatedAt = time.Now()
    
    r.users[user.ID] = user
    r.emails[user.Email] = user
    
    return user, nil
}

// Step 4: Usage in service (same code works with any implementation)
type AuthService struct {
    userRepo UserRepository // Interface, not concrete type!
    jwtSecret string
}

func (s *AuthService) Register(req *RegisterRequest) (*User, error) {
    // Business logic stays the same regardless of storage implementation
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        return nil, err
    }
    
    user := &User{
        Email:        req.Email,
        PasswordHash: string(hashedPassword),
        FirstName:    req.FirstName,
        LastName:     req.LastName,
    }
    
    // This works with PostgreSQL, MySQL, in-memory, or any implementation!
    return s.userRepo.Create(user)
}
```

### 3. Dependency Injection Pattern 🔌

**What is Dependency Injection?**
Instead of a class creating its own dependencies (like making your own tools), Dependency Injection is like having someone give you the tools you need. This makes your code more flexible and testable.

```mermaid
graph TB
    subgraph "Without Dependency Injection (Bad)"
        A1[Service] --> B1["Creates Repository<br/>Directly"]
        B1 --> C1["Hard to Test<br/>Tightly Coupled"]
    end
    
    subgraph "With Dependency Injection (Good)"
        A2[Service] --> B2["Receives Repository<br/>via Constructor"]
        B2 --> C2["Easy to Test<br/>Loosely Coupled"]
    end
    
    style A1 fill:#ffebee
    style C1 fill:#ffebee
    style A2 fill:#e8f5e8
    style C2 fill:#e8f5e8
```

**Bad Example (Tight Coupling):**
```go
// ❌ Service creates its own dependencies
type BadAuthService struct {
    userRepo *postgresUserRepository // Concrete type!
    jwtSecret string
}

func NewBadAuthService(dbConnection *sql.DB, jwtSecret string) *BadAuthService {
    // Creating dependency inside the service
    userRepo := &postgresUserRepository{db: dbConnection}
    
    return &BadAuthService{
        userRepo: userRepo, // Can't swap implementations
        jwtSecret: jwtSecret,
    }
}

// Problems:
// 1. Can't use different database implementations
// 2. Hard to test (requires real database)
// 3. Violates Single Responsibility Principle
```

**Good Example (Dependency Injection):**
```go
// ✅ Service receives dependencies from outside
type AuthService struct {
    userRepo  UserRepository // Interface!
    jwtSecret string
}

// Constructor injection - dependencies provided from outside
func NewAuthService(userRepo UserRepository, jwtSecret string) *AuthService {
    return &AuthService{
        userRepo:  userRepo,  // Any implementation of UserRepository
        jwtSecret: jwtSecret,
    }
}

func (s *AuthService) Login(email, password string) (string, *User, error) {
    // Get user from repository (any implementation)
    user, err := s.userRepo.GetByEmail(email)
    if err != nil {
        return "", nil, errors.New("invalid credentials")
    }
    
    // Verify password
    err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
    if err != nil {
        return "", nil, errors.New("invalid credentials")
    }
    
    // Generate JWT token
    token, err := s.generateJWT(user)
    if err != nil {
        return "", nil, err
    }
    
    return token, user, nil
}

// Benefits:
// 1. Can inject PostgreSQL repo for production
// 2. Can inject in-memory repo for testing
// 3. Easy to add new database implementations
// 4. Service focuses only on business logic
```

**Dependency Injection in Action (main.go):**
```go
func main() {
    // 1. Create database connection
    db := database.Connect()
    
    // 2. Create repository implementations
    userRepo := repository.NewPostgresUserRepository(db)
    accountRepo := repository.NewPostgresAccountRepository(db)
    
    // 3. Inject dependencies into services
    authService := service.NewAuthService(userRepo, "jwt-secret")
    accountService := service.NewAccountService(accountRepo, userRepo)
    
    // 4. Inject services into handlers
    authHandler := handler.NewAuthHandler(authService)
    accountHandler := handler.NewAccountHandler(accountService)
    
    // 5. Setup routes
    router := gin.Default()
    router.POST("/auth/login", authHandler.Login)
    router.GET("/accounts", middleware.Auth(authService), accountHandler.GetAccounts)
    
    router.Run(":8080")
}
```

**Testing with Dependency Injection:**
```go
func TestAuthService_Login_Success(t *testing.T) {
    // Arrange - Create mock repository
    mockRepo := &MockUserRepository{}
    authService := NewAuthService(mockRepo, "test-secret")
    
    expectedUser := &User{
        ID:           1,
        Email:        "test@example.com",
        PasswordHash: "$2a$10$...", // bcrypt hash of "password"
    }
    
    // Setup mock expectation
    mockRepo.On("GetByEmail", "test@example.com").Return(expectedUser, nil)
    
    // Act
    token, user, err := authService.Login("test@example.com", "password")
    
    // Assert
    assert.NoError(t, err)
    assert.NotEmpty(t, token)
    assert.Equal(t, expectedUser.Email, user.Email)
    mockRepo.AssertExpectations(t)
}
```

### 4. Service Layer Pattern 📏

**What is Service Layer Pattern?**
The Service Layer is like a restaurant manager. Customers (HTTP handlers) don't go directly to the kitchen (database). Instead, they talk to the manager (service) who coordinates with the kitchen, handles special requests, and ensures everything runs smoothly.

```mermaid
graph TB
    subgraph "Service Layer Responsibilities"
        A[HTTP Request] --> B[Service Layer]
        B --> C[Business Logic Validation]
        B --> D[Transaction Management]
        B --> E[Data Orchestration]
        B --> F[Error Handling]
    end
    
    B --> G[Repository 1]
    B --> H[Repository 2]
    B --> I[Repository 3]
    
    style B fill:#e8f5e8
```

**Why Service Layer?**
- 🎯 **Single Responsibility**: Each service handles one business domain
- 🔄 **Reusable**: Business logic can be used by different interfaces
- 🔒 **Transaction Management**: Handles database transactions safely
- 🧪 **Testable**: Business logic isolated from HTTP concerns

**Detailed Example - Transaction Service:**

```go
type TransactionService struct {
    accountRepo     AccountRepository
    transactionRepo TransactionRepository
    userRepo        UserRepository
}

func NewTransactionService(
    accountRepo AccountRepository,
    transactionRepo TransactionRepository,
    userRepo UserRepository,
) *TransactionService {
    return &TransactionService{
        accountRepo:     accountRepo,
        transactionRepo: transactionRepo,
        userRepo:        userRepo,
    }
}

// Deposit money - coordinating multiple operations
func (s *TransactionService) Deposit(userID int, accountID int, amount float64, description string) (*Transaction, error) {
    // Step 1: Validate business rules
    if amount <= 0 {
        return nil, errors.New("deposit amount must be positive")
    }
    
    // Step 2: Verify user owns the account
    account, err := s.accountRepo.GetByID(accountID)
    if err != nil {
        return nil, fmt.Errorf("account not found: %w", err)
    }
    
    if account.UserID != userID {
        return nil, errors.New("unauthorized: account does not belong to user")
    }
    
    // Step 3: Calculate new balance
    balanceBefore := account.Balance
    balanceAfter := balanceBefore + amount
    
    // Step 4: Create transaction record
    transaction := &Transaction{
        AccountID:     accountID,
        Type:          "deposit",
        Amount:        amount,
        BalanceBefore: balanceBefore,
        BalanceAfter:  balanceAfter,
        Description:   description,
        ReferenceID:   generateReferenceID(),
        CreatedAt:     time.Now(),
    }
    
    // Step 5: Update account balance
    err = s.accountRepo.UpdateBalance(accountID, balanceAfter)
    if err != nil {
        return nil, fmt.Errorf("failed to update balance: %w", err)
    }
    
    // Step 6: Save transaction record
    savedTransaction, err := s.transactionRepo.Create(transaction)
    if err != nil {
        // Rollback balance update if transaction creation fails
        s.accountRepo.UpdateBalance(accountID, balanceBefore)
        return nil, fmt.Errorf("failed to create transaction: %w", err)
    }
    
    return savedTransaction, nil
}

// Withdraw money - with additional business rules
func (s *TransactionService) Withdraw(userID int, accountID int, amount float64, description string) (*Transaction, error) {
    // Step 1: Validate business rules
    if amount <= 0 {
        return nil, errors.New("withdrawal amount must be positive")
    }
    
    // Step 2: Get account and verify ownership
    account, err := s.accountRepo.GetByID(accountID)
    if err != nil {
        return nil, fmt.Errorf("account not found: %w", err)
    }
    
    if account.UserID != userID {
        return nil, errors.New("unauthorized: account does not belong to user")
    }
    
    // Step 3: Check if account is active
    if !account.IsActive {
        return nil, errors.New("account is inactive")
    }
    
    // Step 4: Validate sufficient balance
    if !account.CanWithdraw(amount) {
        return nil, errors.New("insufficient balance")
    }
    
    // Step 5: Calculate new balance
    balanceBefore := account.Balance
    balanceAfter := balanceBefore - amount
    
    // Step 6: Create transaction record
    transaction := &Transaction{
        AccountID:     accountID,
        Type:          "withdrawal",
        Amount:        amount,
        BalanceBefore: balanceBefore,
        BalanceAfter:  balanceAfter,
        Description:   description,
        ReferenceID:   generateReferenceID(),
        CreatedAt:     time.Now(),
    }
    
    // Step 7: Update account balance
    err = s.accountRepo.UpdateBalance(accountID, balanceAfter)
    if err != nil {
        return nil, fmt.Errorf("failed to update balance: %w", err)
    }
    
    // Step 8: Save transaction record
    savedTransaction, err := s.transactionRepo.Create(transaction)
    if err != nil {
        // Rollback balance update if transaction creation fails
        s.accountRepo.UpdateBalance(accountID, balanceBefore)
        return nil, fmt.Errorf("failed to create transaction: %w", err)
    }
    
    return savedTransaction, nil
}

// Get transaction history with pagination
func (s *TransactionService) GetTransactionHistory(userID int, accountID int, page, limit int) ([]*Transaction, error) {
    // Verify user owns the account
    account, err := s.accountRepo.GetByID(accountID)
    if err != nil {
        return nil, fmt.Errorf("account not found: %w", err)
    }
    
    if account.UserID != userID {
        return nil, errors.New("unauthorized: account does not belong to user")
    }
    
    // Get transactions with pagination
    offset := (page - 1) * limit
    return s.transactionRepo.GetByAccountID(accountID, limit, offset)
}

func generateReferenceID() string {
    return fmt.Sprintf("TXN-%d-%s", time.Now().Unix(), generateRandomString(8))
}
```

### 5. Middleware Pattern 🚪

**What is Middleware?**
Middleware is like security guards at different checkpoints. Before a request reaches your main application code, it passes through various middleware that can authenticate users, log requests, validate data, etc.

```mermaid
graph LR
    A[Client Request] --> B[CORS Middleware]
    B --> C[Logging Middleware]
    C --> D[Authentication Middleware]
    D --> E[Validation Middleware]
    E --> F[Your Handler]
    F --> G[Response]
    
    style B fill:#ffecb3
    style C fill:#e1f5fe
    style D fill:#ffcdd2
    style E fill:#e8f5e8
    style F fill:#f3e5f5
```

**Authentication Middleware Example:**

```go
func AuthMiddleware(authService AuthService) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Step 1: Extract Authorization header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Authorization header is required",
                "code":  "MISSING_AUTH_HEADER",
            })
            c.Abort() // Stop processing, don't call next handlers
            return
        }
        
        // Step 2: Validate Bearer token format
        if !strings.HasPrefix(authHeader, "Bearer ") {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid authorization header format. Expected 'Bearer <token>'",
                "code":  "INVALID_AUTH_FORMAT",
            })
            c.Abort()
            return
        }
        
        // Step 3: Extract token
        token := strings.TrimPrefix(authHeader, "Bearer ")
        if token == "" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Token is required",
                "code":  "MISSING_TOKEN",
            })
            c.Abort()
            return
        }
        
        // Step 4: Validate token and get user
        user, err := authService.ValidateToken(token)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid or expired token",
                "code":  "INVALID_TOKEN",
            })
            c.Abort()
            return
        }
        
        // Step 5: Store user information in context for later use
        c.Set("user", user)
        c.Set("user_id", user.ID)
        
        // Step 6: Continue to next handler
        c.Next()
    }
}

// Usage in routes
func SetupRoutes(authService AuthService, accountHandler *AccountHandler) *gin.Engine {
    router := gin.Default()
    
    // Public routes (no authentication needed)
    router.POST("/auth/login", authHandler.Login)
    router.POST("/auth/register", authHandler.Register)
    router.GET("/health", healthHandler.Health)
    
    // Protected routes (authentication required)
    protected := router.Group("/api/v1")
    protected.Use(AuthMiddleware(authService)) // Apply middleware to all routes in this group
    {
        protected.GET("/accounts", accountHandler.GetAccounts)
        protected.POST("/accounts/:id/deposit", accountHandler.Deposit)
        protected.POST("/accounts/:id/withdraw", accountHandler.Withdraw)
        protected.GET("/accounts/:id/transactions", accountHandler.GetTransactions)
    }
    
    return router
}

// In handler, access user from context
func (h *AccountHandler) GetAccounts(c *gin.Context) {
    // Get user from middleware context
    user, exists := c.Get("user")
    if !exists {
        c.JSON(500, gin.H{"error": "User not found in context"})
        return
    }
    
    userID, _ := c.Get("user_id")
    
    accounts, err := h.accountService.GetAccountsByUserID(userID.(int))
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }
    
    c.JSON(200, gin.H{"accounts": accounts})
}
```

**Logging Middleware Example:**

```go
func LoggingMiddleware() gin.HandlerFunc {
    return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
        return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\
",
            param.ClientIP,
            param.TimeStamp.Format(time.RFC1123),
            param.Method,
            param.Path,
            param.Request.Proto,
            param.StatusCode,
            param.Latency,
            param.Request.UserAgent(),
            param.ErrorMessage,
        )
    })
}

// CORS Middleware for API access
func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("Access-Control-Allow-Origin", "*")
        c.Header("Access-Control-Allow-Credentials", "true")
        c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
        c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        
        c.Next()
    }
}
```

### 6. Strategy Pattern (Advanced) 🎯

**What is Strategy Pattern?**
Strategy pattern allows you to define a family of algorithms and make them interchangeable. It's like having different payment methods (credit card, PayPal, bank transfer) - all serve the same purpose but work differently.

```mermaid
graph TB
    Client[Transaction Service] --> Strategy[Transaction Processor Interface]
    Strategy --> Impl1[Instant Transfer]
    Strategy --> Impl2[Batch Processing]
    Strategy --> Impl3[External Payment Gateway]
    
    style Strategy fill:#e3f2fd
```

**Example - Different Transaction Processing Strategies:**

```go
// Strategy interface
type TransactionProcessor interface {
    ProcessTransaction(transaction *Transaction) error
    GetProcessingFee(amount float64) float64
    GetProcessingTime() time.Duration
}

// Instant processing strategy
type InstantProcessor struct{}

func (p *InstantProcessor) ProcessTransaction(transaction *Transaction) error {
    // Process immediately
    log.Printf("Processing transaction %s instantly", transaction.ReferenceID)
    return nil
}

func (p *InstantProcessor) GetProcessingFee(amount float64) float64 {
    return amount * 0.01 // 1% fee for instant processing
}

func (p *InstantProcessor) GetProcessingTime() time.Duration {
    return time.Second * 1
}

// Batch processing strategy
type BatchProcessor struct {
    batchQueue []*Transaction
}

func (p *BatchProcessor) ProcessTransaction(transaction *Transaction) error {
    // Add to batch queue
    p.batchQueue = append(p.batchQueue, transaction)
    log.Printf("Added transaction %s to batch queue", transaction.ReferenceID)
    return nil
}

func (p *BatchProcessor) GetProcessingFee(amount float64) float64 {
    return amount * 0.005 // 0.5% fee for batch processing
}

func (p *BatchProcessor) GetProcessingTime() time.Duration {
    return time.Hour * 1 // Processed every hour
}

// Service using strategy pattern
type EnhancedTransactionService struct {
    processor TransactionProcessor
    // ... other dependencies
}

func (s *EnhancedTransactionService) SetProcessor(processor TransactionProcessor) {
    s.processor = processor
}

func (s *EnhancedTransactionService) ProcessPayment(transaction *Transaction) error {
    // Calculate fee based on strategy
    fee := s.processor.GetProcessingFee(transaction.Amount)
    transaction.ProcessingFee = fee
    
    // Process using selected strategy
    return s.processor.ProcessTransaction(transaction)
}

// Usage
func main() {
    service := &EnhancedTransactionService{}
    
    // Use instant processing for urgent transactions
    if isUrgent {
        service.SetProcessor(&InstantProcessor{})
    } else {
        service.SetProcessor(&BatchProcessor{})
    }
    
    service.ProcessPayment(transaction)
}
```

---

## 🏗️ Architecture Deep Dive

> **For Beginners**: This section explains WHY we organize code this way and HOW each part works together.

### The Big Picture - How Everything Connects

```mermaid
graph TB
    subgraph "Client Layer"
        A[Web Browser]
        B[Mobile App]
        C[API Client]
    end
    
    subgraph "HTTP Layer (Gin Framework)"
        D[Router]
        E[Middleware Stack]
        F[Handlers]
    end
    
    subgraph "Service Layer (Business Logic)"
        G[Auth Service]
        H[Account Service]
        I[Transaction Service]
    end
    
    subgraph "Repository Layer (Data Access)"
        J[User Repository]
        K[Account Repository]
        L[Transaction Repository]
    end
    
    subgraph "Database Layer"
        M[(PostgreSQL)]
        N[Migrations]
        O[Indexes]
    end
    
    subgraph "External Services"
        P[JWT Token Validation]
        Q[Password Hashing]
        R[Configuration]
    end
    
    A --> D
    B --> D
    C --> D
    
    D --> E
    E --> F
    
    F --> G
    F --> H
    F --> I
    
    G --> J
    H --> K
    I --> L
    
    J --> M
    K --> M
    L --> M
    
    G --> P
    G --> Q
    
    style G fill:#e8f5e8
    style H fill:#e8f5e8
    style I fill:#e8f5e8
    style J fill:#f3e5f5
    style K fill:#f3e5f5
    style L fill:#f3e5f5
```

### Why This Architecture? 🤔

**1. Separation of Concerns**
Each layer has ONE job:
- 🌐 **HTTP Layer**: Handle web requests and responses
- 💼 **Service Layer**: Implement business rules and logic
- 🗺️ **Repository Layer**: Access and manage data
- 📊 **Domain Layer**: Define business entities and rules

**2. Dependency Direction (Dependency Inversion Principle)**
```mermaid
graph TD
    A[HTTP Layer] --> B[Service Layer]
    B --> C[Repository Layer]
    C --> D[Domain Layer]
    
    A -.-> E["Depends on Abstractions<br/>(Interfaces)"]
    B -.-> E
    C -.-> E
    
    style E fill:#e3f2fd
```

**Benefits:**
- ✅ **Easy Testing**: Mock any layer independently
- ✅ **Flexible**: Change database without affecting business logic
- ✅ **Maintainable**: Changes in one layer don't break others
- ✅ **Scalable**: Each layer can be optimized separately

### Real-World Request Flow 🌊

Let's trace a complete user login request:

```mermaid
sequenceDiagram
    participant C as Client
    participant H as HTTP Handler
    participant M as Auth Middleware
    participant S as Auth Service
    participant R as User Repository
    participant D as Database
    
    C->>H: POST /auth/login {email, password}
    H->>H: Validate request format
    H->>S: Login(email, password)
    S->>R: GetByEmail(email)
    R->>D: SELECT * FROM users WHERE email = ?
    D-->>R: Return user data
    R-->>S: Return User object
    S->>S: Verify password with bcrypt
    S->>S: Generate JWT token
    S-->>H: Return token + user
    H-->>C: JSON response with token
```

**Step-by-Step Explanation:**

1. **Client Request**: User submits login form
2. **HTTP Handler**: Validates JSON format, extracts email/password
3. **Service Layer**: Implements login business logic
4. **Repository Layer**: Queries database for user
5. **Database**: Returns user data if found
6. **Service Layer**: Verifies password, generates JWT
7. **HTTP Handler**: Returns response to client

### File Organization Strategy 📁

**Why This Structure?**

```
go-bank/
├── cmd/api/                    # Application entry points
│   └── main.go                 # Main application bootstrap
│
├── internal/                  # Private application code
│   ├── domain/                # 🔵 Core business logic (innermost layer)
│   │   ├── user.go            # User entity with business rules
│   │   ├── account.go         # Account entity with validation
│   │   ├── transaction.go     # Transaction entity
│   │   └── interfaces.go      # Repository & service contracts
│   │
│   ├── repository/            # 🟣 Data access implementations
│   │   ├── user_repository.go
│   │   ├── account_repository.go
│   │   └── transaction_repository.go
│   │
│   ├── service/               # 🟢 Business logic orchestration
│   │   ├── auth_service.go
│   │   ├── account_service.go
│   │   └── transaction_service.go
│   │
│   ├── handler/               # 🟠 HTTP request/response handling
│   │   ├── auth_handler.go
│   │   ├── account_handler.go
│   │   └── transaction_handler.go
│   │
│   ├── middleware/            # Cross-cutting concerns
│   │   ├── auth.go
│   │   ├── logging.go
│   │   └── cors.go
│   │
│   ├── config/                # Configuration management
│   │   └── config.go
│   │
│   └── database/              # Database connection & migrations
│       └── database.go
│
├── migrations/                # Database schema versions
│   ├── 000001_initial_schema.up.sql
│   └── 000001_initial_schema.down.sql
│
├── test/                      # All tests
│   ├── unit/                  # Unit tests with mocks
│   └── integration/           # Integration tests
│
├── pkg/                       # Public packages (reusable)
│   ├── logger/
│   └── utils/
│
├── docs/                      # Documentation
├── scripts/                   # Build and deployment scripts
├── config.yaml                # Configuration file
├── docker-compose.yml         # Development environment
├── Dockerfile                 # Production container
└── Makefile                   # Development automation
```

**Key Principles:**

1. **`internal/` vs `pkg/`**:
   - `internal/`: Private to this application, can't be imported by other projects
   - `pkg/`: Public packages that could be reused by other projects

2. **Layer Separation**:
   - Each layer in its own directory
   - Clear dependency direction (outer → inner)
   - No circular dependencies

3. **Domain-First Design**:
   - Domain entities define the core business
   - Other layers adapt to domain requirements
   - Business rules live in domain, not in database or HTTP handlers

### Database Design Strategy 🗺️

**Entity Relationship Diagram:**

```mermaid
erDiagram
    USERS {
        int id PK
        string email UK
        string password_hash
        string first_name
        string last_name
        timestamp created_at
        timestamp updated_at
    }
    
    ACCOUNTS {
        int id PK
        int user_id FK
        string account_number UK
        decimal balance
        string currency
        string account_type
        boolean is_active
        timestamp created_at
        timestamp updated_at
    }
    
    TRANSACTIONS {
        int id PK
        int account_id FK
        string transaction_type
        decimal amount
        decimal balance_before
        decimal balance_after
        string description
        string reference_id UK
        timestamp created_at
    }
    
    USERS ||--o{ ACCOUNTS : "owns"
    ACCOUNTS ||--o{ TRANSACTIONS : "has"
```

**Design Decisions Explained:**

1. **Primary Keys**: Auto-incrementing integers for performance
2. **Foreign Keys**: Enforce referential integrity
3. **Unique Constraints**: Prevent duplicate emails and account numbers
4. **Decimal Types**: For precise money calculations (avoid floating point errors)
5. **Audit Fields**: `created_at`, `updated_at` for tracking changes
6. **Reference IDs**: Human-readable transaction identifiers

**Indexes for Performance:**
```sql
-- Fast user lookups by email (login)
CREATE INDEX idx_users_email ON users(email);

-- Fast account lookups by user
CREATE INDEX idx_accounts_user_id ON accounts(user_id);

-- Fast transaction history queries
CREATE INDEX idx_transactions_account_id_created_at ON transactions(account_id, created_at DESC);
```

### Configuration Management ⚙️

**Why Viper for Configuration?**

```mermaid
graph TB
    A["config.yaml<br/>(Default Values)"] --> D[Viper Config Manager]
    B["Environment Variables<br/>(Production Overrides)"] --> D
    C["Command Line Flags<br/>(Development Overrides)"] --> D
    
    D --> E[Application Configuration]
    
    style D fill:#e8f5e8
    style E fill:#e1f5fe
```

**Configuration Hierarchy (Highest to Lowest Priority):**
1. Command line flags
2. Environment variables (with `GOBANK_` prefix)
3. YAML configuration file
4. Default values in code

**Example Configuration Structure:**
```go
type Config struct {
    Environment string `mapstructure:"environment"`
    Debug       bool   `mapstructure:"debug"`
    LogLevel    string `mapstructure:"loglevel"`
    
    Server struct {
        Host string `mapstructure:"host"`
        Port string `mapstructure:"port"`
    } `mapstructure:"server"`
    
    Database struct {
        Host            string        `mapstructure:"host"`
        Port            int           `mapstructure:"port"`
        User            string        `mapstructure:"user"`
        Password        string        `mapstructure:"password"`
        DBName          string        `mapstructure:"dbname"`
        SSLMode         string        `mapstructure:"sslmode"`
        MaxOpenConns    int           `mapstructure:"maxopenconns"`
        MaxIdleConns    int           `mapstructure:"maxidleconns"`
        ConnMaxLifetime time.Duration `mapstructure:"connmaxlifetime"`
    } `mapstructure:"database"`
    
    JWT struct {
        Secret     string        `mapstructure:"secret"`
        Expiration time.Duration `mapstructure:"expiration"`
    } `mapstructure:"jwt"`
}
```

### Security Architecture 🔒

**Multi-Layer Security Approach:**

```mermaid
graph TB
    A[Client Request] --> B[HTTPS/TLS Layer]
    B --> C[Rate Limiting Middleware]
    C --> D[CORS Middleware]
    D --> E[Request Validation]
    E --> F[JWT Authentication]
    F --> G[Authorization Checks]
    G --> H[Input Sanitization]
    H --> I[SQL Parameterization]
    I --> J[Business Logic]
    
    style F fill:#ffcdd2
    style G fill:#ffcdd2
    style H fill:#ffcdd2
    style I fill:#ffcdd2
```

**Security Features Implemented:**

1. **Password Security**:
   - bcrypt hashing with salt
   - Minimum password requirements
   - No plain text storage

2. **JWT Token Security**:
   - Short expiration times
   - Secure secret key management
   - Token validation on every request

3. **Database Security**:
   - Parameterized queries (no SQL injection)
   - Connection pooling with limits
   - Prepared statements

4. **API Security**:
   - Request validation and sanitization
   - Error messages don't leak sensitive info
   - CORS configuration

### Error Handling Strategy ⚠️

**Error Handling Flow:**

```mermaid
graph TB
    A[Error Occurs] --> B{Error Type?}
    B -->|Validation Error| C[400 Bad Request]
    B -->|Authentication Error| D[401 Unauthorized]
    B -->|Authorization Error| E[403 Forbidden]
    B -->|Not Found Error| F[404 Not Found]
    B -->|Business Logic Error| G[422 Unprocessable Entity]
    B -->|Database Error| H[500 Internal Server Error]
    B -->|Unknown Error| I[500 Internal Server Error]
    
    C --> J[Log Error Details]
    D --> J
    E --> J
    F --> J
    G --> J
    H --> J
    I --> J
    
    J --> K[Return Safe Error Message]
```

**Error Types and Handling:**

```go
// Custom error types
type AppError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details string `json:"details,omitempty"`
}

// Common errors
var (
    ErrUserNotFound       = &AppError{"USER_NOT_FOUND", "User not found", ""}
    ErrInvalidCredentials = &AppError{"INVALID_CREDENTIALS", "Invalid email or password", ""}
    ErrInsufficientBalance = &AppError{"INSUFFICIENT_BALANCE", "Insufficient account balance", ""}
    ErrAccountInactive    = &AppError{"ACCOUNT_INACTIVE", "Account is not active", ""}
)

// Error handling in handlers
func (h *AuthHandler) Login(c *gin.Context) {
    // ... validation code ...
    
    token, user, err := h.authService.Login(req.Email, req.Password)
    if err != nil {
        // Don't expose internal error details
        if err == ErrInvalidCredentials {
            c.JSON(401, gin.H{"error": err.Message, "code": err.Code})
        } else {
            // Log full error for debugging
            log.Printf("Login error: %v", err)
            c.JSON(500, gin.H{"error": "Internal server error", "code": "INTERNAL_ERROR"})
        }
        return
    }
    
    c.JSON(200, gin.H{"token": token, "user": user})
}
```

---

## 📝 Step-by-Step Implementation Guide

> **For Beginners**: Follow these steps in order. Each phase builds on the previous one. Don't skip ahead!

### Prerequisites Check ✅

Before starting, ensure you have:

```bash
# Check Go version (need 1.21+)
go version

# Check if Docker is installed
docker --version

# Check if Docker Compose is available
docker-compose --version

# Check if Make is installed (optional but helpful)
make --version
```

### Phase 1: Project Foundation 🏗️

#### Step 1.1: Initialize Go Module

```bash
# Create project directory
mkdir go-bank
cd go-bank

# Initialize Go module
go mod init github.com/your-username/go-bank

# Create directory structure
mkdir -p cmd/api
mkdir -p internal/{domain,repository,service,handler,config,database,middleware}
mkdir -p migrations
mkdir -p test/{unit,integration}
mkdir -p pkg/{logger,utils}
mkdir -p docs
mkdir -p scripts
```

**What we created:**
- `cmd/api/`: Application entry point
- `internal/`: Private application code (Clean Architecture layers)
- `migrations/`: Database schema versions
- `test/`: All test files
- `pkg/`: Reusable packages
- `docs/`: Documentation
- `scripts/`: Automation scripts

#### Step 1.2: Add Dependencies

```bash
# Web framework and HTTP utilities
go get github.com/gin-gonic/gin

# Database and migrations
go get github.com/lib/pq  # PostgreSQL driver
go get -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate
go get github.com/golang-migrate/migrate/v4/database/postgres
go get github.com/golang-migrate/migrate/v4/source/file

# Configuration management
go get github.com/spf13/viper

# Authentication and security
go get github.com/golang-jwt/jwt/v4
go get golang.org/x/crypto/bcrypt

# Testing framework
go get github.com/stretchr/testify

# Validation
go get github.com/go-playground/validator/v10
```

#### Step 1.3: Create Basic Configuration

**File:** `config.yaml`
```yaml
# Go Bank Configuration
environment: development
debug: true
loglevel: info

server:
  host: localhost
  port: "8080"

database:
  host: localhost
  port: 5432
  user: postgres
  password: password
  dbname: gobank
  sslmode: disable
  maxopenconns: 25
  maxidleconns: 25
  connmaxlifetime: "5m"

jwt:
  secret: "your-secret-key-change-this-in-production"
  expiration: "24h"
```

### Phase 2: Domain Layer (Core Business Logic) 🔵

> **Remember**: Domain layer is the heart of your application. It contains business rules and entities.

#### Step 2.1: Create User Entity (Complete Implementation)

**File:** `internal/domain/user.go`

```go
package domain

import (
	"errors"
	"time"
)

// User represents a bank customer
type User struct {
	ID           int       `json:"id" db:"id"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"` // Never expose password hash in JSON
	FirstName    string    `json:"first_name" db:"first_name"`
	LastName     string    `json:"last_name" db:"last_name"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// CreateUserRequest represents the request to create a new user
type CreateUserRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=6"`
	FirstName string `json:"first_name" binding:"required,min=2"`
	LastName  string `json:"last_name" binding:"required,min=2"`
}

// LoginRequest represents the login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// UserResponse represents the user response (without sensitive data)
type UserResponse struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	CreatedAt time.Time `json:"created_at"`
}

// ToResponse converts User to UserResponse
func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		CreatedAt: u.CreatedAt,
	}
}

// Validate validates user data
func (u *User) Validate() error {
	if u.Email == "" {
		return errors.New("email is required")
	}
	if u.FirstName == "" {
		return errors.New("first name is required")
	}
	if u.LastName == "" {
		return errors.New("last name is required")
	}
	return nil
}
```

**🔍 Go Syntax Explained:**

1. **Package Declaration**: `package domain`
   - Every Go file starts with a package declaration
   - `domain` is the package name - groups related functionality
   - All files in same directory must have same package name

2. **Imports**: `import ("errors", "time")`
   - Import external packages needed in this file
   - `errors` - Go's built-in error handling
   - `time` - Go's time and date handling

3. **Struct Definition**: `type User struct {}`
   - `type` keyword defines a new type
   - `struct` is like a class in other languages
   - Contains fields (properties) with types

4. **Struct Tags**: `json:"id" db:"id"`
   - Metadata attached to struct fields
   - `json:"id"` - how field appears in JSON
   - `db:"id"` - how field maps to database column
   - `json:"-"` - excludes field from JSON (security!)

5. **Method Definition**: `func (u *User) ToResponse() *UserResponse`
   - `func` declares a function
   - `(u *User)` - receiver, makes this a method on User
   - `*User` - pointer receiver (can modify the struct)
   - `*UserResponse` - returns pointer to UserResponse

6. **Error Handling**: `return errors.New("message")`
   - Go uses explicit error returns
   - `errors.New()` creates a new error with message
   - Functions often return `(result, error)`

**💡 Key Concepts:**
- **Struct Tags**: Used by libraries to control serialization/validation
- **Pointer Receivers**: `*User` allows method to modify the struct
- **Validation**: Business rules enforced in domain layer
- **Response DTOs**: Separate types for API responses (security)

**🔧 Commands to create this file:**
```bash
# Create the domain directory
mkdir -p internal/domain

# Create the user.go file
touch internal/domain/user.go

# Add the content above to the file
# You can use any text editor: nano, vim, VS Code, etc.
nano internal/domain/user.go
```

#### Step 2.2: Create Account Entity (Complete Implementation)

**File:** `internal/domain/account.go`

```go
package domain

import (
	"errors"
	"time"
)

// AccountType represents the type of account
type AccountType string

const (
	AccountTypeSavings  AccountType = "savings"
	AccountTypeChecking AccountType = "checking"
)

// Account represents a bank account
type Account struct {
	ID            int         `json:"id" db:"id"`
	UserID        int         `json:"user_id" db:"user_id"`
	AccountNumber string      `json:"account_number" db:"account_number"`
	Balance       float64     `json:"balance" db:"balance"`
	Currency      string      `json:"currency" db:"currency"`
	AccountType   AccountType `json:"account_type" db:"account_type"`
	IsActive      bool        `json:"is_active" db:"is_active"`
	CreatedAt     time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at" db:"updated_at"`
}

// AccountResponse represents the account response
type AccountResponse struct {
	ID            int         `json:"id"`
	AccountNumber string      `json:"account_number"`
	Balance       float64     `json:"balance"`
	Currency      string      `json:"currency"`
	AccountType   AccountType `json:"account_type"`
	IsActive      bool        `json:"is_active"`
	CreatedAt     time.Time   `json:"created_at"`
}

// CreateAccountRequest represents the request to create a new account
type CreateAccountRequest struct {
	UserID      int         `json:"user_id" binding:"required"`
	Currency    string      `json:"currency" binding:"required,len=3"`
	AccountType AccountType `json:"account_type" binding:"required"`
}

// BalanceResponse represents the balance response
type BalanceResponse struct {
	AccountID     int     `json:"account_id"`
	AccountNumber string  `json:"account_number"`
	Balance       float64 `json:"balance"`
	Currency      string  `json:"currency"`
}

// ToResponse converts Account to AccountResponse
func (a *Account) ToResponse() *AccountResponse {
	return &AccountResponse{
		ID:            a.ID,
		AccountNumber: a.AccountNumber,
		Balance:       a.Balance,
		Currency:      a.Currency,
		AccountType:   a.AccountType,
		IsActive:      a.IsActive,
		CreatedAt:     a.CreatedAt,
	}
}

// ToBalanceResponse converts Account to BalanceResponse
func (a *Account) ToBalanceResponse() *BalanceResponse {
	return &BalanceResponse{
		AccountID:     a.ID,
		AccountNumber: a.AccountNumber,
		Balance:       a.Balance,
		Currency:      a.Currency,
	}
}

// Validate validates account data
func (a *Account) Validate() error {
	if a.UserID <= 0 {
		return errors.New("user ID is required")
	}
	if a.AccountNumber == "" {
		return errors.New("account number is required")
	}
	if a.Balance < 0 {
		return errors.New("balance cannot be negative")
	}
	if a.Currency == "" {
		return errors.New("currency is required")
	}
	return nil
}

// CanWithdraw checks if the account has sufficient balance for withdrawal
func (a *Account) CanWithdraw(amount float64) bool {
	return a.IsActive && a.Balance >= amount && amount > 0
}

// CanDeposit checks if the account can accept deposits
func (a *Account) CanDeposit(amount float64) bool {
	return a.IsActive && amount > 0
}
```

**🔍 Go Syntax Explained:**

1. **Custom Types**: `type AccountType string`
   - Creates a new type based on existing type (`string`)
   - Provides type safety - can't accidentally mix strings with AccountType
   - Allows methods to be defined on the custom type

2. **Constants**: `const (AccountTypeSavings AccountType = "savings")`
   - `const` declares constants (immutable values)
   - Grouped in parentheses for multiple constants
   - Type is specified (`AccountType`) for type safety

3. **Struct Embedding/Composition**: Multiple struct types in same file
   - `Account` - main entity
   - `AccountResponse` - for API responses
   - `CreateAccountRequest` - for API requests
   - Each serves different purpose (separation of concerns)

4. **Boolean Logic**: `return a.IsActive && a.Balance >= amount && amount > 0`
   - `&&` is logical AND operator
   - `>=` is greater than or equal operator
   - `>` is greater than operator
   - Returns `true` only if ALL conditions are met

5. **Float Comparison**: `a.Balance >= amount`
   - `float64` is Go's standard floating-point type
   - Used for money calculations (though `decimal` types are better for production)
   - Go is statically typed - can't mix `int` and `float64`

**💡 Key Banking Concepts:**
- **Business Rules**: `CanWithdraw()` and `CanDeposit()` encode banking logic
- **Data Validation**: `Validate()` ensures data integrity
- **Response DTOs**: Separate types for API responses
- **Type Safety**: Custom `AccountType` prevents invalid values

**🔧 Commands:**
```bash
# Create the account.go file
touch internal/domain/account.go

# Edit the file (use your preferred editor)
code internal/domain/account.go  # VS Code
# or
vim internal/domain/account.go   # Vim
# or
nano internal/domain/account.go  # Nano

# Test compilation
go build ./internal/domain
```

#### Step 2.3: Create Transaction Entity

**File:** [`internal/domain/transaction.go`](internal/domain/transaction.go)

```go
package domain

import (
	"errors"
	"fmt"
	"time"
)

type TransactionType string

const (
	TransactionTypeDeposit    TransactionType = "deposit"
	TransactionTypeWithdrawal TransactionType = "withdrawal"
	TransactionTypeTransfer   TransactionType = "transfer"
)

// Transaction represents a banking transaction
type Transaction struct {
	ID            int             `json:"id" db:"id"`
	AccountID     int             `json:"account_id" db:"account_id"`
	Type          TransactionType `json:"transaction_type" db:"transaction_type"`
	Amount        float64         `json:"amount" db:"amount"`
	BalanceBefore float64         `json:"balance_before" db:"balance_before"`
	BalanceAfter  float64         `json:"balance_after" db:"balance_after"`
	Description   string          `json:"description" db:"description"`
	ReferenceID   string          `json:"reference_id" db:"reference_id"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
}

// Business rules
func (t *Transaction) Validate() error {
	if t.AccountID <= 0 {
		return errors.New("account ID is required")
	}
	
	if t.Amount <= 0 {
		return errors.New("transaction amount must be positive")
	}
	
	if t.Type == "" {
		return errors.New("transaction type is required")
	}
	
	if t.ReferenceID == "" {
		t.ReferenceID = t.GenerateReferenceID()
	}
	
	return nil
}

// GenerateReferenceID creates a unique transaction reference
func (t *Transaction) GenerateReferenceID() string {
	timestamp := time.Now().Unix()
	return fmt.Sprintf("TXN-%d-%s", timestamp, generateRandomString(8))
}

// Helper function to generate random string
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// IsDebit returns true if transaction reduces account balance
func (t *Transaction) IsDebit() bool {
	return t.Type == TransactionTypeWithdrawal
}

// IsCredit returns true if transaction increases account balance
func (t *Transaction) IsCredit() bool {
	return t.Type == TransactionTypeDeposit
}
```

#### Step 2.4: Define Interfaces (Contracts)

**File:** [`internal/domain/interfaces.go`](internal/domain/interfaces.go)

```go
package domain

// Repository interfaces define contracts for data access
type UserRepository interface {
	Create(user *User) (*User, error)
	GetByID(id int) (*User, error)
	GetByEmail(email string) (*User, error)
	Update(user *User) (*User, error)
	Delete(id int) error
}

type AccountRepository interface {
	Create(account *Account) (*Account, error)
	GetByID(id int) (*Account, error)
	GetByUserID(userID int) ([]*Account, error)
	GetByAccountNumber(accountNumber string) (*Account, error)
	UpdateBalance(id int, balance float64) error
	Update(account *Account) (*Account, error)
	Delete(id int) error
}

type TransactionRepository interface {
	Create(transaction *Transaction) (*Transaction, error)
	GetByID(id int) (*Transaction, error)
	GetByAccountID(accountID int, limit, offset int) ([]*Transaction, error)
	GetByReferenceID(referenceID string) (*Transaction, error)
}

// Service interfaces define business logic contracts
type AuthService interface {
	Register(req *RegisterRequest) (*User, string, error)
	Login(email, password string) (string, *User, error)
	ValidateToken(token string) (*User, error)
	GenerateToken(user *User) (string, error)
}

type AccountService interface {
	CreateAccount(userID int, accountType AccountType) (*Account, error)
	GetAccountsByUserID(userID int) ([]*Account, error)
	GetAccountByID(id int) (*Account, error)
	DeactivateAccount(id int) error
}

type TransactionService interface {
	Deposit(userID, accountID int, amount float64, description string) (*Transaction, error)
	Withdraw(userID, accountID int, amount float64, description string) (*Transaction, error)
	GetTransactionHistory(userID, accountID int, page, limit int) ([]*Transaction, error)
	GetTransactionByID(id int) (*Transaction, error)
}

### Phase 3: Database Layer 🗺️

#### Step 3.1: Create Migration Files

**File:** `migrations/000001_initial_schema.up.sql`

```sql
-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create accounts table
CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_number VARCHAR(50) UNIQUE NOT NULL,
    balance DECIMAL(15,2) DEFAULT 0.00 CHECK (balance >= 0),
    currency VARCHAR(3) DEFAULT 'USD',
    account_type VARCHAR(20) DEFAULT 'savings',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    transaction_type VARCHAR(20) NOT NULL,
    amount DECIMAL(15,2) NOT NULL CHECK (amount > 0),
    balance_before DECIMAL(15,2) NOT NULL,
    balance_after DECIMAL(15,2) NOT NULL,
    description TEXT,
    reference_id VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_account_number ON accounts(account_number);
CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_reference_id ON transactions(reference_id);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at DESC);

-- Create triggers for updated_at columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_accounts_updated_at BEFORE UPDATE ON accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

**File:** `migrations/000001_initial_schema.down.sql`

```sql
-- Drop triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_accounts_updated_at ON accounts;
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_transactions_created_at;
DROP INDEX IF EXISTS idx_transactions_reference_id;
DROP INDEX IF EXISTS idx_transactions_account_id;
DROP INDEX IF EXISTS idx_accounts_account_number;
DROP INDEX IF EXISTS idx_accounts_user_id;
DROP INDEX IF EXISTS idx_users_email;

-- Drop tables (order matters due to foreign keys)
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;
```

#### Step 3.2: Database Connection and Configuration

**File:** [`internal/database/database.go`](internal/database/database.go)

```go
package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"github.com/zain/go-bank/internal/config"
)

// Connect establishes a connection to PostgreSQL database
func Connect(cfg *config.Config) (*sql.DB, error) {
	// Build connection string
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.DBName,
		cfg.Database.SSLMode,
	)

	// Open database connection
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// RunMigrations applies database migrations
func RunMigrations(db *sql.DB) error {
	// Create migrate driver
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migrate driver: %w", err)
	}

	// Create file source
	source, err := (&file.File{}).Open("file://migrations")
	if err != nil {
		return fmt.Errorf("failed to open migration files: %w", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithInstance("file", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// Run migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
```

### Phase 4: Repository Layer (Data Access) 🗺️

#### Step 4.1: User Repository Implementation

**File:** [`internal/repository/user_repository.go`](internal/repository/user_repository.go)

```go
package repository

import (
	"database/sql"
	"fmt"

	"github.com/zain/go-bank/internal/domain"
)

type userRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *sql.DB) domain.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(user *domain.User) (*domain.User, error) {
	// Normalize email before storing
	user.NormalizeEmail()
	
	// Validate user data
	if err := user.Validate(); err != nil {
		return nil, err
	}

	query := `
		INSERT INTO users (email, password_hash, first_name, last_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		RETURNING id, created_at, updated_at`

	err := r.db.QueryRow(
		query,
		user.Email,
		user.PasswordHash,
		user.FirstName,
		user.LastName,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (r *userRepository) GetByID(id int) (*domain.User, error) {
	user := &domain.User{}
	query := `
		SELECT id, email, password_hash, first_name, last_name, created_at, updated_at
		FROM users
		WHERE id = $1`

	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (r *userRepository) GetByEmail(email string) (*domain.User, error) {
	user := &domain.User{}
	query := `
		SELECT id, email, password_hash, first_name, last_name, created_at, updated_at
		FROM users
		WHERE email = $1`

	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (r *userRepository) Update(user *domain.User) (*domain.User, error) {
	if err := user.Validate(); err != nil {
		return nil, err
	}

	query := `
		UPDATE users
		SET email = $2, first_name = $3, last_name = $4, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		RETURNING updated_at`

	err := r.db.QueryRow(
		query,
		user.ID,
		user.Email,
		user.FirstName,
		user.LastName,
	).Scan(&user.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return user, nil
}

func (r *userRepository) Delete(id int) error {
	query := `DELETE FROM users WHERE id = $1`
	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}
```

### Phase 5: Service Layer (Business Logic) 📏

#### Step 5.1: Configuration Service

**File:** [`internal/config/config.go`](internal/config/config.go)

```go
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for our application
type Config struct {
	Environment string `mapstructure:"environment"`
	Debug       bool   `mapstructure:"debug"`
	LogLevel    string `mapstructure:"loglevel"`

	Server struct {
		Host string `mapstructure:"host"`
		Port string `mapstructure:"port"`
	} `mapstructure:"server"`

	Database struct {
		Host            string        `mapstructure:"host"`
		Port            int           `mapstructure:"port"`
		User            string        `mapstructure:"user"`
		Password        string        `mapstructure:"password"`
		DBName          string        `mapstructure:"dbname"`
		SSLMode         string        `mapstructure:"sslmode"`
		MaxOpenConns    int           `mapstructure:"maxopenconns"`
		MaxIdleConns    int           `mapstructure:"maxidleconns"`
		ConnMaxLifetime time.Duration `mapstructure:"connmaxlifetime"`
	} `mapstructure:"database"`

	JWT struct {
		Secret     string        `mapstructure:"secret"`
		Expiration time.Duration `mapstructure:"expiration"`
	} `mapstructure:"jwt"`
}

// Load reads configuration from file and environment variables
func Load() (*Config, error) {
	v := viper.New()

	// Set configuration file name and paths
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	v.AddConfigPath("$HOME/.gobank")

	// Environment variables configuration
	v.SetEnvPrefix("GOBANK")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Set default values
	setDefaults(v)

	// Read configuration file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found; ignore error as we have defaults
	}

	// Unmarshal configuration
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	// Application defaults
	v.SetDefault("environment", "development")
	v.SetDefault("debug", false)
	v.SetDefault("loglevel", "info")

	// Server defaults
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", "8080")

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "password")
	v.SetDefault("database.dbname", "gobank")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("database.maxopenconns", 25)
	v.SetDefault("database.maxidleconns", 25)
	v.SetDefault("database.connmaxlifetime", "5m")

	// JWT defaults
	v.SetDefault("jwt.secret", "your-secret-key-change-this-in-production")
	v.SetDefault("jwt.expiration", "24h")
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.JWT.Secret == "your-secret-key-change-this-in-production" && c.Environment == "production" {
		return fmt.Errorf("JWT secret must be changed in production")
	}

	if c.Database.DBName == "" {
		return fmt.Errorf("database name is required")
	}

	return nil
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}
```

### Phase 6: Application Bootstrap & Commands 🚀

#### Step 6.1: Main Application Entry Point (Complete Implementation)

**File:** `cmd/api/main.go`

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zain/go-bank/internal/config"
	"github.com/zain/go-bank/internal/database"
	"github.com/zain/go-bank/internal/domain"
	"github.com/zain/go-bank/internal/handler"
	"github.com/zain/go-bank/internal/middleware"
	"github.com/zain/go-bank/internal/repository"
	"github.com/zain/go-bank/internal/service"
	"github.com/zain/go-bank/pkg/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Initialize logger
	logger := logger.New(cfg.LogLevel)

	// Initialize database
	db, err := database.Connect(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database", err)
	}
	defer db.Close()

	// Run migrations
	if err := database.Migrate(cfg.Database.URL); err != nil {
		logger.Fatal("Failed to run migrations", err)
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	accountRepo := repository.NewAccountRepository(db)
	transactionRepo := repository.NewTransactionRepository(db)

	// Initialize services
	authService := service.NewAuthService(userRepo, cfg.JWT.Secret)
	accountService := service.NewAccountService(accountRepo, transactionRepo)
	transactionService := service.NewTransactionService(transactionRepo, accountRepo)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService)
	accountHandler := handler.NewAccountHandler(accountService)
	transactionHandler := handler.NewTransactionHandler(transactionService)

	// Setup router
	router := setupRouter(cfg, authService, authHandler, accountHandler, transactionHandler)

	// Create server
	server := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Starting server on port " + cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", err)
	}

	logger.Info("Server exited")
}

func setupRouter(cfg *config.Config, authService domain.AuthService, authHandler *handler.AuthHandler, accountHandler *handler.AccountHandler, transactionHandler *handler.TransactionHandler) *gin.Engine {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS())
	router.Use(middleware.RequestID())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// API routes
	api := router.Group("/api/v1")
	{
		// Auth routes (public)
		auth := api.Group("/auth")
		{
			auth.POST("/signup", authHandler.SignUp)
			auth.POST("/login", authHandler.Login)
		}

		// Protected routes
		protected := api.Group("/")
		protected.Use(middleware.AuthMiddleware(authService))
		{
			// Account routes
			accounts := protected.Group("/accounts")
			{
				accounts.GET("/", accountHandler.GetAccounts)
				accounts.GET("/:id", accountHandler.GetAccount)
				accounts.GET("/:id/balance", accountHandler.GetBalance)
			}

			// Transaction routes
			transactions := protected.Group("/transactions")
			{
				transactions.POST("/deposit", transactionHandler.Deposit)
				transactions.POST("/withdraw", transactionHandler.Withdraw)
				transactions.GET("/", transactionHandler.GetTransactions)
				transactions.GET("/:id", transactionHandler.GetTransaction)
			}
		}
	}

	return router
}
```

**🔍 Go Syntax Explained:**

1. **Package main**: `package main`
   - Special package that creates an executable program
   - Must have a `main()` function as entry point
   - Other packages can't have `main` package

2. **Import Block**: `import ("context", "log", ...)`
   - Groups multiple imports
   - Standard library imports first, then third-party, then local
   - Local imports use the module name: `github.com/zain/go-bank/internal/config`

3. **Error Handling Pattern**: `if err != nil { log.Fatal(...) }`
   - Go's standard error handling
   - `log.Fatal()` prints error and exits program
   - Always check errors explicitly in Go

4. **Dependency Injection**: `authService := service.NewAuthService(userRepo, cfg.JWT.Secret)`
   - Constructor pattern in Go
   - Pass dependencies as parameters
   - Returns interface, not concrete type

5. **Goroutines**: `go func() { ... }()`
   - `go` keyword starts concurrent execution
   - Anonymous function `func() { ... }()` runs in background
   - Used for non-blocking server start

6. **Channels**: `quit := make(chan os.Signal, 1)`
   - `chan` creates a channel for communication between goroutines
   - `os.Signal` is the type of data the channel carries
   - `1` is buffer size (can hold 1 value)

7. **Signal Handling**: `signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)`
   - Listens for OS signals (Ctrl+C, kill command)
   - Enables graceful shutdown
   - `<-quit` blocks until signal received

8. **Context with Timeout**: `ctx, cancel := context.WithTimeout(..., 30*time.Second)`
   - `context` manages deadlines, cancellation, and timeouts
   - `cancel` is a function to cancel the context
   - `defer cancel()` ensures cleanup happens

9. **HTTP Server**: `server := &http.Server{Addr: ":8080", Handler: router}`
   - `&` creates a pointer to the struct
   - Struct literal initialization with field names
   - `Handler` is the Gin router

**💡 Key Concepts:**
- **Graceful Shutdown**: Server stops accepting new requests but finishes existing ones
- **Dependency Injection**: All dependencies passed in, not created inside
- **Layer Separation**: Config → Database → Repositories → Services → Handlers
- **Middleware**: Cross-cutting concerns applied to all routes
- **Route Groups**: Organize related endpoints with common middleware

#### Step 6.2: Complete Makefile for Development Commands

**File:** `Makefile`

```makefile
# Makefile for Go Bank Application

# Variables
APP_NAME=go-bank
DOCKER_IMAGE=go-bank:latest
DOCKER_COMPOSE=docker-compose.yml

# Build the application
build:
	@echo "Building Go Bank application..."
	go build -o bin/$(APP_NAME) cmd/api/main.go

# Run the application locally
run:
	@echo "Running Go Bank application..."
	go run cmd/api/main.go

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

# Start services with Docker Compose
docker-up:
	@echo "Starting services with Docker Compose..."
	docker-compose -f $(DOCKER_COMPOSE) up -d

# Stop services
docker-down:
	@echo "Stopping services..."
	docker-compose -f $(DOCKER_COMPOSE) down

# View logs
docker-logs:
	@echo "Viewing logs..."
	docker-compose -f $(DOCKER_COMPOSE) logs -f

# Clean up Docker
docker-clean:
	@echo "Cleaning up Docker..."
	docker-compose -f $(DOCKER_COMPOSE) down -v --remove-orphans
	docker system prune -f

# Database migration
migrate-up:
	@echo "Running database migrations..."
	migrate -path migrations -database "postgres://postgres:password@localhost:5432/gobank?sslmode=disable" up

# Rollback migrations
migrate-down:
	@echo "Rolling back database migrations..."
	migrate -path migrations -database "postgres://postgres:password@localhost:5432/gobank?sslmode=disable" down

# Create new migration
migrate-create:
	@echo "Creating new migration..."
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir migrations -seq $$name

# Database management
db-start:
	@echo "Starting PostgreSQL database..."
	docker run --name gobank-postgres \
		-e POSTGRES_USER=postgres \
		-e POSTGRES_PASSWORD=password \
		-e POSTGRES_DB=gobank \
		-p 5432:5432 \
		-v gobank_postgres_data:/var/lib/postgresql/data \
		-d postgres:15-alpine || echo "Container already exists, starting..."
	docker start gobank-postgres 2>/dev/null || true
	@echo "Waiting for database to be ready..."
	@sleep 3

db-stop:
	@echo "Stopping PostgreSQL database..."
	docker stop gobank-postgres 2>/dev/null || true

db-restart: db-stop db-start
	@echo "Database restarted"

db-shell:
	@echo "Connecting to PostgreSQL shell..."
	docker exec -it gobank-postgres psql -U postgres -d gobank

db-logs:
	@echo "Viewing PostgreSQL logs..."
	docker logs -f gobank-postgres

db-reset:
	@echo "Resetting database (WARNING: This will delete all data!)..."
	docker stop gobank-postgres 2>/dev/null || true
	docker rm gobank-postgres 2>/dev/null || true
	docker volume rm gobank_postgres_data 2>/dev/null || true
	$(MAKE) db-start
	@echo "Database reset complete"

db-test-connection:
	@echo "Testing database connection..."
	docker exec gobank-postgres pg_isready -U postgres

db-backup:
	@echo "Creating database backup..."
	mkdir -p backups
	docker exec gobank-postgres pg_dump -U postgres gobank > backups/gobank_backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "Backup created in backups/ directory"

db-restore:
	@echo "Restoring database from backup..."
	@read -p "Enter backup file path: " backup_file; \
	docker exec -i gobank-postgres psql -U postgres -d gobank < $$backup_file

db-init-data:
	@echo "Loading initial test data..."
	docker exec -i gobank-postgres psql -U postgres -d gobank < scripts/init_data.sql
	@echo "Test data loaded. Demo user: demo@gobank.com, password: password"

# Complete setup with database
setup-full: setup-dev db-start
	@echo "Waiting for database to be ready..."
	@sleep 5
	$(MAKE) migrate-up
	$(MAKE) db-init-data
	@echo "\n✅ Full setup complete!"
	@echo "Database is running with test data."
	@echo "Demo user: demo@gobank.com, password: password"
	@echo "You can now run: make run"

# Help
help:
	@echo "Available commands:"
	@echo "  build         - Build the application"
	@echo "  run           - Run the application locally"
	@echo "  deps          - Install dependencies"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  fmt           - Format code"
	@echo "  lint          - Lint code"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-up     - Start services with Docker Compose"
	@echo "  docker-down   - Stop services"
	@echo "  docker-logs   - View logs"
	@echo "  docker-clean  - Clean up Docker"
	@echo "  migrate-up    - Run database migrations"
	@echo "  migrate-down  - Rollback database migrations"
	@echo "  migrate-create- Create new migration"
	@echo "  db-start      - Start PostgreSQL database"
	@echo "  db-stop       - Stop PostgreSQL database"
	@echo "  db-restart    - Restart PostgreSQL database"
	@echo "  db-shell      - Connect to database shell"
	@echo "  db-logs       - View database logs"
	@echo "  db-reset      - Reset database (WARNING: deletes data)"
	@echo "  db-test-connection - Test database connection"
	@echo "  db-backup     - Create database backup"
	@echo "  db-restore    - Restore database from backup"
	@echo "  db-init-data  - Load initial test data"
	@echo "  setup-full    - Complete setup with database"
	@echo "  help          - Show this help message"

.PHONY: build run deps test test-coverage fmt lint docker-build docker-up docker-down docker-logs docker-clean migrate-up migrate-down migrate-create db-start db-stop db-restart db-shell db-logs db-reset db-test-connection db-backup db-restore db-init-data setup-full help
```

**🔍 Makefile Syntax Explained:**

1. **Variables**: `APP_NAME=go-bank`
   - Define reusable values
   - Used with `$(APP_NAME)` syntax
   - No spaces around `=`

2. **Targets**: `build:`
   - Each command you can run
   - Followed by colon `:`
   - Commands below must be indented with TAB (not spaces!)

3. **Echo Commands**: `@echo "Building..."`
   - `@` suppresses showing the command itself
   - `echo` prints message to user
   - Provides feedback about what's happening

4. **Go Commands**:
   - `go build -o bin/$(APP_NAME) cmd/api/main.go` - Compile to executable
   - `go run cmd/api/main.go` - Compile and run directly
   - `go mod download` - Download dependencies
   - `go mod tidy` - Clean up go.mod file
   - `go test -v ./...` - Run all tests verbosely
   - `go fmt ./...` - Format all Go files

5. **Docker Commands**:
   - `docker build -t $(DOCKER_IMAGE) .` - Build image with tag
   - `docker run --name gobank-postgres` - Create and run container
   - `docker exec -it gobank-postgres psql` - Execute command in container
   - `docker logs -f gobank-postgres` - Follow container logs

6. **Error Handling**: `2>/dev/null || true`
   - `2>/dev/null` redirects error output to nowhere
   - `|| true` ensures command doesn't fail if container doesn't exist
   - Prevents Makefile from stopping on non-critical errors

7. **Dependencies**: `db-restart: db-stop db-start`
   - `db-restart` depends on `db-stop` and `db-start`
   - Make runs dependencies in order
   - Allows composing complex operations

8. **User Input**: `@read -p "Enter migration name: " name`
   - `read` gets user input
   - `-p` shows prompt
   - `$$name` uses the variable (double $ in Makefile)

9. **Phony Targets**: `.PHONY: build run ...`
   - Tells Make these aren't file names
   - Prevents conflicts with files of same name
   - Always runs the command

**💻 Essential Commands Explained:**

```bash
# Development workflow commands
make deps          # Download Go dependencies
make build         # Compile the application
make run           # Start the development server
make test          # Run all tests
make fmt           # Format Go code

# Database management commands
make db-start      # Start PostgreSQL in Docker
make db-stop       # Stop PostgreSQL
make migrate-up    # Apply database migrations
make db-init-data  # Load sample data
make db-shell      # Connect to database

# Docker commands
make docker-build  # Build Docker image
make docker-up     # Start all services
make docker-down   # Stop all services
make docker-logs   # View application logs

# Complete setup (run this first!)
make setup-full    # Sets up everything automatically

# Get help
make help          # Show all available commands
```

**🚀 Quick Start Commands:**

```bash
# 1. First time setup (run once)
make setup-full

# 2. Start the application
make run

# 3. Test the API
curl http://localhost:8080/health

# 4. View database
make db-shell
```
```

---

## 🧪 Testing Strategies

> **For Beginners**: Testing ensures your code works correctly and helps prevent bugs in production.

### Testing Pyramid Explained

```mermaid
graph TB
    subgraph "Testing Pyramid"
        A["E2E Tests<br/>(Few, Slow, Expensive)"]
        B["Integration Tests<br/>(Some, Medium Speed)"]
        C["Unit Tests<br/>(Many, Fast, Cheap)"]
    end
    
    A --> B
    B --> C
    
    style C fill:#e8f5e8
    style B fill:#fff3e0
    style A fill:#ffebee
```

### Unit Testing with Mocks 🧪

**Why Unit Tests?**
- Fast execution (milliseconds)
- Test individual components in isolation
- Easy to debug when they fail
- Provide documentation for your code

#### Step 6.1: Create Mock Repositories

**File:** `test/mocks/user_repository_mock.go`

```go
package mocks

import (
	"github.com/stretchr/testify/mock"
	"github.com/zain/go-bank/internal/domain"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *domain.User) (*domain.User, error) {
	args := m.Called(user)
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(id int) (*domain.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*domain.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *domain.User) (*domain.User, error) {
	args := m.Called(user)
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Delete(id int) error {
	args := m.Called(id)
	return args.Error(0)
}
```

#### Step 6.2: Write Service Unit Tests

**File:** `test/unit/auth_service_test.go`

```go
package unit

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/zain/go-bank/internal/domain"
	"github.com/zain/go-bank/internal/service"
	"github.com/zain/go-bank/test/mocks"
)

func TestAuthService_Register_Success(t *testing.T) {
	// Arrange
	mockRepo := new(mocks.MockUserRepository)
	authService := service.NewAuthService(mockRepo, "test-secret", time.Hour*24)

	req := &domain.RegisterRequest{
		Email:     "test@example.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	// Mock expectations
	mockRepo.On("GetByEmail", "test@example.com").Return(nil, errors.New("user not found"))
	mockRepo.On("Create", mock.AnythingOfType("*domain.User")).Return(&domain.User{
		ID:        1,
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		CreatedAt: time.Now(),
	}, nil)

	// Act
	user, token, err := authService.Register(req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.NotEmpty(t, token)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "John", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)

	// Verify mock expectations
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_UserAlreadyExists(t *testing.T) {
	// Arrange
	mockRepo := new(mocks.MockUserRepository)
	authService := service.NewAuthService(mockRepo, "test-secret", time.Hour*24)

	req := &domain.RegisterRequest{
		Email:     "existing@example.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	existingUser := &domain.User{
		ID:    1,
		Email: "existing@example.com",
	}

	// Mock expectations
	mockRepo.On("GetByEmail", "existing@example.com").Return(existingUser, nil)

	// Act
	user, token, err := authService.Register(req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "already exists")

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_Success(t *testing.T) {
	// Arrange
	mockRepo := new(mocks.MockUserRepository)
	authService := service.NewAuthService(mockRepo, "test-secret", time.Hour*24)

	// Create a user with hashed password
	hashedPassword := "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi" // "password"
	user := &domain.User{
		ID:           1,
		Email:        "test@example.com",
		PasswordHash: hashedPassword,
		FirstName:    "John",
		LastName:     "Doe",
	}

	// Mock expectations
	mockRepo.On("GetByEmail", "test@example.com").Return(user, nil)

	// Act
	token, loggedInUser, err := authService.Login("test@example.com", "password")

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotNil(t, loggedInUser)
	assert.Equal(t, user.Email, loggedInUser.Email)

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_InvalidCredentials(t *testing.T) {
	// Arrange
	mockRepo := new(mocks.MockUserRepository)
	authService := service.NewAuthService(mockRepo, "test-secret", time.Hour*24)

	// Mock expectations - user not found
	mockRepo.On("GetByEmail", "nonexistent@example.com").Return(nil, errors.New("user not found"))

	// Act
	token, user, err := authService.Login("nonexistent@example.com", "password")

	// Assert
	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "invalid credentials")

	mockRepo.AssertExpectations(t)
}

func TestAuthService_ValidateToken_Success(t *testing.T) {
	// Arrange
	mockRepo := new(mocks.MockUserRepository)
	authService := service.NewAuthService(mockRepo, "test-secret", time.Hour*24)

	user := &domain.User{
		ID:        1,
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
	}

	// Generate a valid token
	token, err := authService.GenerateToken(user)
	assert.NoError(t, err)

	// Mock expectations
	mockRepo.On("GetByID", 1).Return(user, nil)

	// Act
	validatedUser, err := authService.ValidateToken(token)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, validatedUser)
	assert.Equal(t, user.ID, validatedUser.ID)
	assert.Equal(t, user.Email, validatedUser.Email)

	mockRepo.AssertExpectations(t)
}
```

### Integration Testing 🔗

**Why Integration Tests?**
- Test how components work together
- Catch issues that unit tests might miss
- Test database interactions
- Verify API endpoints work correctly

#### Step 6.3: Database Integration Tests

**File:** `test/integration/user_repository_test.go`

```go
package integration

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zain/go-bank/internal/domain"
	"github.com/zain/go-bank/internal/repository"
	"github.com/zain/go-bank/test/testutil"
)

func TestUserRepository_Create_Success(t *testing.T) {
	// Setup test database
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	// Create repository
	userRepo := repository.NewUserRepository(db)

	// Create test user
	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hashed_password",
		FirstName:    "John",
		LastName:     "Doe",
	}

	// Act
	createdUser, err := userRepo.Create(user)

	// Assert
	require.NoError(t, err)
	assert.NotZero(t, createdUser.ID)
	assert.Equal(t, "test@example.com", createdUser.Email)
	assert.Equal(t, "John", createdUser.FirstName)
	assert.Equal(t, "Doe", createdUser.LastName)
	assert.NotZero(t, createdUser.CreatedAt)
	assert.NotZero(t, createdUser.UpdatedAt)
}

func TestUserRepository_GetByEmail_Success(t *testing.T) {
	// Setup
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	userRepo := repository.NewUserRepository(db)

	// Create and save a user
	originalUser := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hashed_password",
		FirstName:    "John",
		LastName:     "Doe",
	}
	createdUser, err := userRepo.Create(originalUser)
	require.NoError(t, err)

	// Act
	foundUser, err := userRepo.GetByEmail("test@example.com")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, createdUser.ID, foundUser.ID)
	assert.Equal(t, createdUser.Email, foundUser.Email)
	assert.Equal(t, createdUser.FirstName, foundUser.FirstName)
	assert.Equal(t, createdUser.LastName, foundUser.LastName)
}

func TestUserRepository_GetByEmail_NotFound(t *testing.T) {
	// Setup
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	userRepo := repository.NewUserRepository(db)

	// Act
	user, err := userRepo.GetByEmail("nonexistent@example.com")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "not found")
}
```

#### Step 6.4: Test Utilities

**File:** `test/testutil/database.go`

```go
package testutil

import (
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/zain/go-bank/internal/database"
)

// SetupTestDB creates a test database connection
func SetupTestDB(t *testing.T) *sql.DB {
	// Use test database
	dsn := "host=localhost port=5432 user=postgres password=password dbname=gobank_test sslmode=disable"
	
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	
	// Test connection
	err = db.Ping()
	require.NoError(t, err)
	
	// Run migrations
	err = database.RunMigrations(db)
	require.NoError(t, err)
	
	return db
}

// CleanupTestDB cleans up test database
func CleanupTestDB(t *testing.T, db *sql.DB) {
	// Clean up tables
	_, err := db.Exec("TRUNCATE transactions, accounts, users RESTART IDENTITY CASCADE")
	require.NoError(t, err)
	
	// Close connection
	err = db.Close()
	require.NoError(t, err)
}
```

### Phase 7: Complete API Testing Commands 🧪

#### Step 7.1: Testing Your Banking API

Once your application is running, you can test all the endpoints using these commands:

**🚀 Quick Setup and Test:**

```bash
# 1. Complete setup (run this first!)
make setup-full

# 2. Start the application
make run

# 3. Open new terminal and test the API
```

**🔍 Health Check (No Authentication Required):**

```bash
# Test if server is running
curl -X GET http://localhost:8080/health

# Expected response:
# {"status":"healthy"}
```

**🔑 Authentication Endpoints:**

```bash
# 1. Register a new user
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "password123",
    "first_name": "John",
    "last_name": "Doe"
  }'

# Expected response:
# {
#   "message": "User created successfully",
#   "user": {
#     "id": 1,
#     "email": "john.doe@example.com",
#     "first_name": "John",
#     "last_name": "Doe",
#     "created_at": "2024-01-01T10:00:00Z"
#   },
#   "token": "eyJhbGciOiJIUzI1NiIs..."
# }

# 2. Login with existing user (demo user from setup)
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "demo@gobank.com",
    "password": "password"
  }'

# Save the token from response for next commands
TOKEN="your-jwt-token-here"
```

**💰 Account Management (Authentication Required):**

```bash
# Set your JWT token (replace with actual token from login)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 1. Get all user accounts
curl -X GET http://localhost:8080/api/v1/accounts \
  -H "Authorization: Bearer $TOKEN"

# Expected response:
# {
#   "accounts": [
#     {
#       "id": 1,
#       "account_number": "ACC0000000001",
#       "balance": 1000.00,
#       "currency": "USD",
#       "account_type": "savings",
#       "is_active": true,
#       "created_at": "2024-01-01T10:00:00Z"
#     }
#   ]
# }

# 2. Get specific account details
curl -X GET http://localhost:8080/api/v1/accounts/1 \
  -H "Authorization: Bearer $TOKEN"

# 3. Check account balance
curl -X GET http://localhost:8080/api/v1/accounts/1/balance \
  -H "Authorization: Bearer $TOKEN"

# Expected response:
# {
#   "account_id": 1,
#   "account_number": "ACC0000000001",
#   "balance": 1000.00,
#   "currency": "USD"
# }
```

**💸 Transaction Operations (Authentication Required):**

```bash
# 1. Deposit money
curl -X POST http://localhost:8080/api/v1/transactions/deposit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": 1,
    "amount": 500.00,
    "description": "Salary deposit"
  }'

# Expected response:
# {
#   "message": "Deposit successful",
#   "transaction": {
#     "id": 2,
#     "account_id": 1,
#     "transaction_type": "deposit",
#     "amount": 500.00,
#     "balance_before": 1000.00,
#     "balance_after": 1500.00,
#     "description": "Salary deposit",
#     "reference_id": "TXN-1704110400-ABC12345",
#     "created_at": "2024-01-01T12:00:00Z"
#   }
# }

# 2. Withdraw money
curl -X POST http://localhost:8080/api/v1/transactions/withdraw \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": 1,
    "amount": 200.00,
    "description": "ATM withdrawal"
  }'

# Expected response:
# {
#   "message": "Withdrawal successful",
#   "transaction": {
#     "id": 3,
#     "account_id": 1,
#     "transaction_type": "withdrawal",
#     "amount": 200.00,
#     "balance_before": 1500.00,
#     "balance_after": 1300.00,
#     "description": "ATM withdrawal",
#     "reference_id": "TXN-1704110460-DEF67890",
#     "created_at": "2024-01-01T12:01:00Z"
#   }
# }

# 3. Get transaction history
curl -X GET "http://localhost:8080/api/v1/transactions?account_id=1&page=1&limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Expected response:
# {
#   "transactions": [
#     {
#       "id": 3,
#       "account_id": 1,
#       "transaction_type": "withdrawal",
#       "amount": 200.00,
#       "balance_before": 1500.00,
#       "balance_after": 1300.00,
#       "description": "ATM withdrawal",
#       "reference_id": "TXN-1704110460-DEF67890",
#       "created_at": "2024-01-01T12:01:00Z"
#     },
#     {
#       "id": 2,
#       "account_id": 1,
#       "transaction_type": "deposit",
#       "amount": 500.00,
#       "balance_before": 1000.00,
#       "balance_after": 1500.00,
#       "description": "Salary deposit",
#       "reference_id": "TXN-1704110400-ABC12345",
#       "created_at": "2024-01-01T12:00:00Z"
#     }
#   ],
#   "page": 1,
#   "limit": 10,
#   "total": 2
# }

# 4. Get specific transaction
curl -X GET http://localhost:8080/api/v1/transactions/2 \
  -H "Authorization: Bearer $TOKEN"
```

**⚠️ Error Testing (What happens when things go wrong):**

```bash
# 1. Test without authentication (should get 401)
curl -X GET http://localhost:8080/api/v1/accounts

# Expected response:
# {
#   "error": "Authorization header required",
#   "code": "MISSING_AUTH_HEADER"
# }

# 2. Test with invalid token (should get 401)
curl -X GET http://localhost:8080/api/v1/accounts \
  -H "Authorization: Bearer invalid-token"

# Expected response:
# {
#   "error": "Invalid or expired token",
#   "code": "INVALID_TOKEN"
# }

# 3. Test withdrawal with insufficient funds (should get 422)
curl -X POST http://localhost:8080/api/v1/transactions/withdraw \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": 1,
    "amount": 999999.00,
    "description": "Large withdrawal"
  }'

# Expected response:
# {
#   "error": "Insufficient balance",
#   "code": "INSUFFICIENT_BALANCE"
# }

# 4. Test invalid input (should get 400)
curl -X POST http://localhost:8080/api/v1/transactions/deposit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": 1,
    "amount": -100.00,
    "description": "Negative deposit"
  }'

# Expected response:
# {
#   "error": "Amount must be positive",
#   "code": "INVALID_AMOUNT"
# }
```

**📊 Database Verification Commands:**

```bash
# Connect to database and verify data
make db-shell

# In PostgreSQL shell, run these queries:

# Check users
SELECT id, email, first_name, last_name, created_at FROM users;

# Check accounts
SELECT id, user_id, account_number, balance, currency, account_type, is_active FROM accounts;

# Check transactions
SELECT id, account_id, transaction_type, amount, balance_before, balance_after, description, reference_id, created_at FROM transactions ORDER BY created_at DESC LIMIT 5;

# Exit PostgreSQL shell
\q
```

**🛠️ Troubleshooting Commands:**

```bash
# Check if application is running
ps aux | grep go-bank

# Check if port 8080 is in use
lsof -i :8080

# View application logs (if running with make run)
# Logs will appear in the terminal where you ran 'make run'

# Check database status
make db-test-connection

# View database logs
make db-logs

# Restart database if needed
make db-restart

# Check Docker containers
docker ps

# Reset everything if something is broken
make db-reset
make setup-full
```

**📝 Complete Test Script (Save as test-api.sh):**

```bash
#!/bin/bash

# API Testing Script for Go Bank
set -e  # Exit on any error

BASE_URL="http://localhost:8080"
echo "🏦 Go Bank API Testing Script"
echo "==============================================="

# 1. Health Check
echo "🔍 Testing Health Check..."
response=$(curl -s -X GET $BASE_URL/health)
echo "Health Response: $response"
echo ""

# 2. User Registration
echo "🔑 Testing User Registration..."
registration_response=$(curl -s -X POST $BASE_URL/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "first_name": "Test",
    "last_name": "User"
  }')
echo "Registration Response: $registration_response"
echo ""

# 3. User Login
echo "🔐 Testing User Login..."
login_response=$(curl -s -X POST $BASE_URL/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "demo@gobank.com",
    "password": "password"
  }')
echo "Login Response: $login_response"

# Extract token (you might need jq for this: brew install jq)
if command -v jq &> /dev/null; then
    TOKEN=$(echo $login_response | jq -r '.token')
    echo "Extracted Token: ${TOKEN:0:50}..."
else
    echo "Install jq to automatically extract token: brew install jq"
    echo "Or manually copy token from login response above"
    echo "Continuing with demo..."
    TOKEN="REPLACE_WITH_ACTUAL_TOKEN"
fi
echo ""

# 4. Get Accounts
echo "💰 Testing Get Accounts..."
accounts_response=$(curl -s -X GET $BASE_URL/api/v1/accounts \
  -H "Authorization: Bearer $TOKEN")
echo "Accounts Response: $accounts_response"
echo ""

# 5. Deposit Money
echo "💸 Testing Deposit..."
deposit_response=$(curl -s -X POST $BASE_URL/api/v1/transactions/deposit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": 1,
    "amount": 100.00,
    "description": "Test deposit"
  }')
echo "Deposit Response: $deposit_response"
echo ""

# 6. Check Balance
echo "📊 Testing Balance Check..."
balance_response=$(curl -s -X GET $BASE_URL/api/v1/accounts/1/balance \
  -H "Authorization: Bearer $TOKEN")
echo "Balance Response: $balance_response"
echo ""

echo "✅ API Testing Complete!"
echo "If you see JSON responses above, your API is working correctly."
```

**Make the script executable and run it:**

```bash
# Make script executable
chmod +x test-api.sh

# Run the test script
./test-api.sh
```

---

## 🚀 Deployment & Production

> **For Beginners**: Deployment is the process of making your application available to users in a production environment.

### Production Architecture Overview

```mermaid
graph TB
    subgraph "Load Balancer"
        A[NGINX/HAProxy]
    end
    
    subgraph "Application Layer"
        B[Go Bank Instance 1]
        C[Go Bank Instance 2]
        D[Go Bank Instance 3]
    end
    
    subgraph "Database Layer"
        E[PostgreSQL Primary]
        F[PostgreSQL Replica]
    end
    
    subgraph "Monitoring"
        G[Prometheus]
        H[Grafana]
        I[AlertManager]
    end
    
    Users --> A
    A --> B
    A --> C
    A --> D
    
    B --> E
    C --> E
    D --> E
    E --> F
    
    B --> G
    C --> G
    D --> G
    G --> H
    G --> I
    
    style E fill:#e8f5e8
    style F fill:#f3e5f5
    style G fill:#e1f5fe
```

### Docker Configuration 🐳

#### Step 7.1: Multi-Stage Dockerfile

**File:** `Dockerfile`

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

# Install git and ca-certificates for dependency management
RUN apk update && apk add --no-cache git ca-certificates tzdata

# Create appuser for security
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o main cmd/api/main.go

# Final stage
FROM scratch

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd

# Copy binary and config
COPY --from=builder /build/main /app/
COPY --from=builder /build/config.yaml /app/
COPY --from=builder /build/migrations /app/migrations/

# Use non-root user
USER appuser

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 8080

# Command to run
CMD ["./main"]
```

#### Step 7.2: Production Docker Compose

**File:** `docker-compose.prod.yml`

```yaml
version: '3.8'

services:
  # PostgreSQL Database with persistence
  postgres:
    image: postgres:15-alpine
    container_name: gobank_postgres_prod
    environment:
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: ${DB_NAME}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    networks:
      - gobank_network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Go Bank API with multiple instances
  api-1:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: gobank_api_1
    environment:
      GOBANK_ENVIRONMENT: production
      GOBANK_SERVER_PORT: 8080
      GOBANK_DATABASE_HOST: postgres
      GOBANK_DATABASE_PORT: 5432
      GOBANK_DATABASE_USER: ${DB_USER}
      GOBANK_DATABASE_PASSWORD: ${DB_PASSWORD}
      GOBANK_DATABASE_DBNAME: ${DB_NAME}
      GOBANK_JWT_SECRET: ${JWT_SECRET}
      GOBANK_LOGLEVEL: info
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - gobank_network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  api-2:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: gobank_api_2
    environment:
      GOBANK_ENVIRONMENT: production
      GOBANK_SERVER_PORT: 8080
      GOBANK_DATABASE_HOST: postgres
      GOBANK_DATABASE_PORT: 5432
      GOBANK_DATABASE_USER: ${DB_USER}
      GOBANK_DATABASE_PASSWORD: ${DB_PASSWORD}
      GOBANK_DATABASE_DBNAME: ${DB_NAME}
      GOBANK_JWT_SECRET: ${JWT_SECRET}
      GOBANK_LOGLEVEL: info
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - gobank_network
    restart: unless-stopped

  # NGINX Load Balancer
  nginx:
    image: nginx:alpine
    container_name: gobank_nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - api-1
      - api-2
    networks:
      - gobank_network
    restart: unless-stopped

  # Prometheus for monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: gobank_prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    networks:
      - gobank_network
    restart: unless-stopped

  # Grafana for visualization
  grafana:
    image: grafana/grafana:latest
    container_name: gobank_grafana
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD}
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - gobank_network
    restart: unless-stopped

volumes:
  postgres_data:
  prometheus_data:
  grafana_data:

networks:
  gobank_network:
    driver: bridge
```

### Production Checklist ✅

#### Security Configuration

```yaml
# .env.production
DB_USER=gobank_prod_user
DB_PASSWORD=super_secure_password_here
DB_NAME=gobank_production
JWT_SECRET=very_long_random_secret_key_for_production
GRAFANA_PASSWORD=grafana_admin_password
```

#### Environment Variables Security

```bash
# Use strong, unique passwords
export GOBANK_DATABASE_PASSWORD="$(openssl rand -base64 32)"
export GOBANK_JWT_SECRET="$(openssl rand -base64 64)"

# Use environment-specific configurations
export GOBANK_ENVIRONMENT=production
export GOBANK_DEBUG=false
export GOBANK_LOGLEVEL=info
```

#### NGINX Configuration

**File:** `nginx.conf`

```nginx
events {
    worker_connections 1024;
}

http {
    upstream gobank_backend {
        server api-1:8080;
        server api-2:8080;
    }

    server {
        listen 80;
        server_name your-domain.com;
        
        # Redirect HTTP to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        # SSL Configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_session_timeout 1d;
        ssl_session_cache shared:MozTLS:10m;
        ssl_session_tickets off;

        # Modern configuration
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;

        # Security headers
        add_header Strict-Transport-Security "max-age=63072000" always;
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

        # Rate limiting
        limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
        limit_req zone=api burst=20 nodelay;

        location / {
            proxy_pass http://gobank_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # Health check endpoint
        location /health {
            proxy_pass http://gobank_backend/health;
            access_log off;
        }
    }
}
```

### Database Backup Strategy 💾

#### Automated Backup Script

**File:** `scripts/backup_db.sh`

```bash
#!/bin/bash

# Database backup script
set -e

# Configuration
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="gobank_production"
DB_USER="gobank_prod_user"
BACKUP_DIR="/backups"
DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/gobank_${DATE}.sql"

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Create backup
echo "Creating database backup..."
pg_dump -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME > $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE

# Remove backups older than 30 days
find $BACKUP_DIR -name "gobank_*.sql.gz" -mtime +30 -delete

echo "Backup completed: ${BACKUP_FILE}.gz"
```

### Monitoring and Observability 📈

#### Application Metrics

**File:** `internal/metrics/metrics.go`

```go
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP metrics
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "HTTP request duration in seconds",
		},
		[]string{"method", "endpoint"},
	)

	// Business metrics
	transactionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "transactions_total",
			Help: "Total number of transactions",
		},
		[]string{"type"},
	)

	accountsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "accounts_total",
			Help: "Total number of active accounts",
		},
	)
)

// RecordHTTPRequest records HTTP request metrics
func RecordHTTPRequest(method, endpoint, status string, duration time.Duration) {
	httpRequestsTotal.WithLabelValues(method, endpoint, status).Inc()
	httpRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// RecordTransaction records transaction metrics
func RecordTransaction(transactionType string) {
	transactionsTotal.WithLabelValues(transactionType).Inc()
}

// SetActiveAccounts sets the number of active accounts
func SetActiveAccounts(count float64) {
	accountsTotal.Set(count)
}
```

### Deployment Commands 🚀

```bash
# Build and deploy to production
make build-prod
make deploy-prod

# Or using Docker
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose -f docker-compose.prod.yml logs -f api-1

# Scale API instances
docker-compose -f docker-compose.prod.yml up -d --scale api-1=3 --scale api-2=3

# Database migration in production
docker-compose -f docker-compose.prod.yml exec api-1 ./main migrate

# Health check
curl https://your-domain.com/health
```

### Production Makefile Commands

**Add to Makefile:**

```makefile
# Production deployment
.PHONY: build-prod deploy-prod backup-db

build-prod:
	@echo "Building production image..."
	docker build -t gobank:latest .

deploy-prod:
	@echo "Deploying to production..."
	docker-compose -f docker-compose.prod.yml up -d

backup-db:
	@echo "Creating database backup..."
	./scripts/backup_db.sh

monitor:
	@echo "Opening monitoring dashboard..."
	open http://localhost:3000

check-health:
	@echo "Checking application health..."
	curl -s http://localhost/health | jq .
```

---

## 🎯 Learning Checkpoints

> **For Beginners**: Use these checkpoints to track your progress and ensure you understand each concept before moving forward.

### Phase 1 Checkpoint: Project Foundation ✅

**Knowledge Check:**
- [ ] I understand what Go modules are and why we use them
- [ ] I can explain the directory structure and why we organize code this way
- [ ] I understand the difference between `internal/` and `pkg/` directories
- [ ] I can create and manage Go dependencies with `go mod`

**Practical Check:**
- [ ] I have successfully initialized a Go module
- [ ] I can add dependencies using `go get`
- [ ] I can explain what each directory in our structure is for
- [ ] I can run `go build` without errors

**Code Understanding:**
```go
// Can you explain what this does?
module github.com/your-username/go-bank

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
)
```

### Phase 2 Checkpoint: Domain Layer ✅

**Knowledge Check:**
- [ ] I understand what business entities are
- [ ] I can explain why validation belongs in the domain layer
- [ ] I understand interfaces and why we define them in the domain
- [ ] I can write business rules and validation methods

**Practical Check:**
- [ ] I can create structs with proper JSON and database tags
- [ ] I can write validation methods for business entities
- [ ] I can define interfaces for repositories and services
- [ ] I understand how to use Go's error handling

**Code Understanding:**
```go
// What design principles does this code demonstrate?
type Account struct {
    ID      int     `json:"id" db:"id"`
    Balance float64 `json:"balance" db:"balance"`
}

func (a *Account) CanWithdraw(amount float64) error {
    if a.Balance < amount {
        return errors.New("insufficient balance")
    }
    return nil
}
```

### Phase 3 Checkpoint: Database Layer ✅

**Knowledge Check:**
- [ ] I understand SQL migrations and why they're important
- [ ] I can explain database relationships (foreign keys, indexes)
- [ ] I understand connection pooling and database configuration
- [ ] I can write SQL queries with proper parameterization

**Practical Check:**
- [ ] I can create database migrations with up/down scripts
- [ ] I can establish database connections with proper configuration
- [ ] I can write SQL queries that prevent injection attacks
- [ ] I can run migrations and understand version control

**Code Understanding:**
```sql
-- What security principles does this query demonstrate?
SELECT id, email, first_name, last_name 
FROM users 
WHERE email = $1
```

### Phase 4 Checkpoint: Repository Layer ✅

**Knowledge Check:**
- [ ] I understand the Repository pattern and its benefits
- [ ] I can explain dependency injection and interface implementation
- [ ] I understand how to handle database errors properly
- [ ] I can explain the difference between interface and implementation

**Practical Check:**
- [ ] I can implement repository interfaces
- [ ] I can write database queries with proper error handling
- [ ] I can use dependency injection in constructors
- [ ] I can test repositories with mock implementations

**Code Understanding:**
```go
// What patterns are demonstrated here?
type userRepository struct {
    db *sql.DB
}

func NewUserRepository(db *sql.DB) domain.UserRepository {
    return &userRepository{db: db}
}

func (r *userRepository) Create(user *domain.User) (*domain.User, error) {
    // Implementation here
}
```

### Phase 5 Checkpoint: Service Layer ✅

**Knowledge Check:**
- [ ] I understand business logic orchestration
- [ ] I can explain JWT tokens and how authentication works
- [ ] I understand password hashing and security best practices
- [ ] I can coordinate between multiple repositories in a service

**Practical Check:**
- [ ] I can implement authentication with JWT
- [ ] I can hash passwords securely with bcrypt
- [ ] I can coordinate database operations in service methods
- [ ] I can handle business logic validation

**Code Understanding:**
```go
// What security measures are implemented here?
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
if err != nil {
    return fmt.Errorf("failed to hash password: %w", err)
}
```

### Phase 6 Checkpoint: HTTP Layer ✅

**Knowledge Check:**
- [ ] I understand HTTP status codes and when to use them
- [ ] I can explain middleware and how it processes requests
- [ ] I understand JSON request/response handling
- [ ] I can implement authentication middleware

**Practical Check:**
- [ ] I can create HTTP handlers with proper error responses
- [ ] I can implement middleware for authentication
- [ ] I can bind JSON requests to structs
- [ ] I can set up routes with different middleware

**Final Knowledge Assessment 🎓**

**Architecture Understanding:**
1. Can you draw the Clean Architecture diagram from memory?
2. Can you explain the dependency direction and why it matters?
3. Can you trace a complete request from HTTP to database and back?

**Design Patterns Mastery:**
1. Repository Pattern: Why and how?
2. Dependency Injection: Benefits and implementation?
3. Service Layer: What belongs here vs. handlers vs. repositories?
4. Middleware: How does it work and what's it used for?

**Security Knowledge:**
1. How do we prevent SQL injection?
2. How do we securely store passwords?
3. How does JWT authentication work?
4. What security headers should we set?

**Production Readiness:**
1. How do we handle configuration in different environments?
2. What metrics should we monitor?
3. How do we deploy with zero downtime?
4. How do we back up and recover data?

---

## 📚 Key Learning Outcomes

### Go Programming Skills Acquired 🚀

**Language Fundamentals:**
- ✅ **Interfaces**: Defining contracts and implementing them
- ✅ **Structs and Methods**: Creating objects with behavior
- ✅ **Error Handling**: Go's explicit error handling approach
- ✅ **Package Management**: Using Go modules and organizing code
- ✅ **Concurrency**: Understanding goroutines and channels (advanced)

**Advanced Go Concepts:**
- ✅ **Dependency Injection**: Constructor injection and interface dependencies
- ✅ **Interface Segregation**: Small, focused interfaces
- ✅ **Composition over Inheritance**: Go's approach to code reuse
- ✅ **Testing**: Unit tests, mocks, and integration testing

### Architecture & Design Patterns Mastered 🏗️

**Clean Architecture:**
- ✅ **Layer Separation**: HTTP → Service → Repository → Domain
- ✅ **Dependency Inversion**: Depending on abstractions, not concretions
- ✅ **Single Responsibility**: Each layer has one job
- ✅ **Testability**: Each layer can be tested independently

**Core Patterns:**
- ✅ **Repository Pattern**: Data access abstraction
- ✅ **Service Layer Pattern**: Business logic orchestration
- ✅ **Dependency Injection**: Loose coupling between components
- ✅ **Middleware Pattern**: Request processing pipeline
- ✅ **Strategy Pattern**: Interchangeable algorithms

### Database & Data Management 🗺️

**Database Design:**
- ✅ **Relational Design**: Tables, relationships, constraints
- ✅ **Migration Management**: Version-controlled schema changes
- ✅ **Indexing Strategy**: Performance optimization
- ✅ **Data Integrity**: ACID properties and constraints

**Data Access:**
- ✅ **SQL Parameterization**: Preventing injection attacks
- ✅ **Connection Pooling**: Resource management
- ✅ **Transaction Management**: Atomic operations
- ✅ **Error Handling**: Graceful failure management

### Security Implementation 🔒

**Authentication & Authorization:**
- ✅ **JWT Tokens**: Stateless authentication
- ✅ **Password Hashing**: bcrypt security
- ✅ **Middleware Authentication**: Request protection
- ✅ **Role-Based Access**: User permission systems

**Application Security:**
- ✅ **Input Validation**: Request sanitization
- ✅ **SQL Injection Prevention**: Parameterized queries
- ✅ **HTTPS Configuration**: Transport security
- ✅ **Security Headers**: XSS, CSRF protection

### DevOps & Production Skills 🚀

**Containerization:**
- ✅ **Docker**: Multi-stage builds and optimization
- ✅ **Docker Compose**: Service orchestration
- ✅ **Production Deployment**: Scalable architecture
- ✅ **Health Checks**: Service monitoring

**Monitoring & Observability:**
- ✅ **Metrics Collection**: Prometheus integration
- ✅ **Log Management**: Structured logging
- ✅ **Health Endpoints**: Service status monitoring
- ✅ **Performance Monitoring**: Request timing and throughput

---

## 🎆 Next Steps & Advanced Topics

### Immediate Next Steps (Week 1-2)

1. **Complete the Implementation**
   - Follow each phase step-by-step
   - Test each component as you build
   - Deploy to your local Docker environment

2. **Add Advanced Features**
   - Money transfer between accounts
   - Account types (checking, savings)
   - Transaction categories and tags
   - Account statements and reports

3. **Improve Security**
   - Rate limiting middleware
   - Account lockout after failed attempts
   - Two-factor authentication
   - Audit logging for sensitive operations

### Intermediate Enhancements (Month 1-2)

1. **Advanced Go Features**
   - Context for request cancellation
   - Goroutines for concurrent processing
   - Channels for communication
   - Worker pools for background tasks

2. **Microservices Architecture**
   - Split into account service, transaction service, auth service
   - gRPC communication between services
   - Service discovery with Consul
   - Circuit breakers for resilience

3. **Advanced Database Features**
   - Read replicas for scalability
   - Database sharding strategies
   - Event sourcing for audit trails
   - CQRS (Command Query Responsibility Segregation)

### Expert-Level Topics (Month 3+)

1. **Event-Driven Architecture**
   - Event sourcing with PostgreSQL events
   - Message queues (RabbitMQ, Apache Kafka)
   - Eventual consistency patterns
   - Saga pattern for distributed transactions

2. **Advanced Security**
   - OAuth 2.0 / OpenID Connect integration
   - Zero-trust security architecture
   - Secrets management with HashiCorp Vault
   - Certificate management and rotation

3. **Production Excellence**
   - Kubernetes deployment and orchestration
   - GitOps with ArgoCD
   - Advanced monitoring with Jaeger tracing
   - Chaos engineering with Chaos Monkey

### Learning Resources 📚

**Books:**
- "Clean Architecture" by Robert C. Martin
- "Building Microservices" by Sam Newman
- "The Go Programming Language" by Alan Donovan
- "Designing Data-Intensive Applications" by Martin Kleppmann

**Online Courses:**
- Go programming fundamentals
- Database design and optimization
- Kubernetes and container orchestration
- Security best practices for web applications

**Practice Projects:**
- Build an e-commerce platform with similar architecture
- Create a social media API
- Implement a real-time chat application
- Design a content management system

---

## 🎉 Congratulations!

You've just learned how to build a production-ready banking application using Go and modern software engineering practices. You now understand:

✨ **Clean Architecture** - How to structure large applications for maintainability
✨ **Design Patterns** - Industry-standard solutions to common problems
✨ **Security Best Practices** - How to protect user data and financial information
✨ **Database Design** - Relational modeling and performance optimization
✨ **Testing Strategies** - Unit tests, integration tests, and mocking
✨ **Production Deployment** - Docker, monitoring, and scalability

These skills are directly applicable to building any large-scale web application, not just banking systems. The patterns and practices you've learned here are used by companies like Google, Netflix, Uber, and thousands of other organizations worldwide.

**Keep building, keep learning, and most importantly - have fun with Go! 🚀**

---

*This tutorial represents industry best practices as of 2024. Continue learning by building more projects, contributing to open source, and staying updated with the Go community.*
