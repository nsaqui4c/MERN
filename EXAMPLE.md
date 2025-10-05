**Key# MERN Stack Code Examples & Reference Notes

This document provides code snippets and detailed explanations for each topic in the 4-week learning plan. Use this as a quick reference when you need help understanding a concept.

---

## Week 1: TypeScript & Backend Basics

### 1. TypeScript - Type Annotations & Interfaces

**What it is:** TypeScript adds static typing to JavaScript, helping catch errors before runtime.

**When to use:** Always use TypeScript in production applications for better code quality and maintainability.

```typescript
// Basic Types
let userId: number = 123;
let email: string = "user@example.com";
let isActive: boolean = true;
let data: any = "can be anything"; // Avoid 'any' when possible

// Array Types
let numbers: number[] = [1, 2, 3];
let strings: Array<string> = ["a", "b", "c"];

// Interface - defines the shape of an object
interface User {
  id: number;
  email: string;
  name: string;
  role: 'admin' | 'user' | 'manager'; // Union of literal types
  profile?: {  // Optional nested object
    avatar: string;
    bio: string;
  };
}

// Using the interface
const user: User = {
  id: 1,
  email: "john@example.com",
  name: "John Doe",
  role: "user"
};

// Type Alias (alternative to interface)
type UserRole = 'admin' | 'user' | 'manager';
type ID = string | number;

// Function with typed parameters and return type
function getUserById(id: ID): User | null {
  // implementation
  return null;
}
```

**Key Points:**
- Interfaces are best for object shapes
- Type aliases are more flexible (unions, intersections)
- Use literal types for fixed string values
- Mark optional properties with `?`

---

### 2. TypeScript - Generics

**What it is:** Generics let you write reusable code that works with multiple types while preserving type safety.

**When to use:** When creating utility functions, API responses, or data structures that work with various types.

```typescript
// Generic Function
function wrapInArray<T>(value: T): T[] {
  return [value];
}

const numArray = wrapInArray(5);        // number[]
const strArray = wrapInArray("hello");  // string[]

// Generic Interface for API Responses
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
  timestamp: Date;
}

interface User {
  id: number;
  name: string;
}

interface Task {
  id: number;
  title: string;
}

// Using the generic interface
const userResponse: ApiResponse<User> = {
  success: true,
  data: { id: 1, name: "John" },
  timestamp: new Date()
};

const taskResponse: ApiResponse<Task[]> = {
  success: true,
  data: [{ id: 1, title: "Complete project" }],
  timestamp: new Date()
};

// Generic Class Example
class DataStore<T> {
  private data: T[] = [];

  add(item: T): void {
    this.data.push(item);
  }

  get(index: number): T | undefined {
    return this.data[index];
  }

  getAll(): T[] {
    return this.data;
  }
}

const userStore = new DataStore<User>();
userStore.add({ id: 1, name: "John" });

// Generic with Constraints
interface HasId {
  id: number;
}

function findById<T extends HasId>(items: T[], id: number): T | undefined {
  return items.find(item => item.id === id);
}
```

**Key Points:**
- Use `<T>` as a type parameter placeholder
- Can constrain generics with `extends`
- Preserves type information throughout your code
- Common convention: T (Type), K (Key), V (Value), E (Element)

---

### 3. TypeScript - Utility Types

**What it is:** Built-in TypeScript types that transform existing types.

**When to use:** To create variations of your types without duplicating code.

```typescript
interface Task {
  id: string;
  title: string;
  description: string;
  status: 'todo' | 'in_progress' | 'review' | 'done';
  priority: 'low' | 'medium' | 'high';
  assignedTo: string;
  createdAt: Date;
  updatedAt: Date;
}

// Partial<T> - Makes all properties optional
type TaskUpdate = Partial<Task>;
const update: TaskUpdate = { 
  status: 'done',
  updatedAt: new Date()
  // Other fields are optional
};

// Pick<T, Keys> - Select specific properties
type TaskSummary = Pick<Task, 'id' | 'title' | 'status'>;
const summary: TaskSummary = {
  id: '123',
  title: 'Fix bug',
  status: 'todo'
};

// Omit<T, Keys> - Exclude specific properties
type TaskCreateInput = Omit<Task, 'id' | 'createdAt' | 'updatedAt'>;
const newTask: TaskCreateInput = {
  title: 'New feature',
  description: 'Add user profile',
  status: 'todo',
  priority: 'high',
  assignedTo: 'user-123'
};

// Required<T> - Makes all properties required
type TaskRequired = Required<Task>;

// Readonly<T> - Makes all properties read-only
type ReadonlyTask = Readonly<Task>;

// Record<K, T> - Creates object type with keys K and values T
type TaskStatusCount = Record<Task['status'], number>;
const statusCounts: TaskStatusCount = {
  todo: 5,
  in_progress: 3,
  review: 2,
  done: 10
};

// ReturnType<T> - Gets return type of a function
function getUser() {
  return { id: 1, name: "John", email: "john@example.com" };
}
type UserReturnType = ReturnType<typeof getUser>;
// { id: number; name: string; email: string; }
```

**Key Points:**
- `Partial` for optional updates
- `Pick` to create smaller interfaces
- `Omit` to exclude fields (like auto-generated IDs)
- `Record` for mapping types
- These reduce code duplication

---

### 4. TypeScript - tsconfig.json Setup

**What it is:** Configuration file that defines TypeScript compiler options.

**When to use:** Every TypeScript project needs this at the root.

```json
{
  "compilerOptions": {
    // Language and Environment
    "target": "ES2020",                    // Output JavaScript version
    "module": "commonjs",                  // Module system (Node.js)
    "lib": ["ES2020"],                     // Include type definitions
    
    // Module Resolution
    "moduleResolution": "node",            // How modules are resolved
    "resolveJsonModule": true,             // Import JSON files
    "esModuleInterop": true,               // Better CommonJS interop
    
    // Type Checking
    "strict": true,                        // Enable all strict checks
    "noImplicitAny": true,                 // Error on implied 'any'
    "strictNullChecks": true,              // Strict null checking
    "strictFunctionTypes": true,           // Strict function types
    "noUnusedLocals": true,                // Error on unused variables
    "noUnusedParameters": true,            // Error on unused params
    "noImplicitReturns": true,             // Function must return value
    
    // Output
    "outDir": "./dist",                    // Output directory
    "rootDir": "./src",                    // Input directory
    "sourceMap": true,                     // Generate .map files
    
    // Other
    "skipLibCheck": true,                  // Skip checking .d.ts files
    "forceConsistentCasingInFileNames": true,
    
    // Path Aliases (optional but useful)
    "baseUrl": "./src",
    "paths": {
      "@models/*": ["models/*"],
      "@controllers/*": ["controllers/*"],
      "@middleware/*": ["middleware/*"],
      "@utils/*": ["utils/*"]
    }
  },
  "include": ["src/**/*"],                 // Files to include
  "exclude": ["node_modules", "dist"]      // Files to exclude
}
```

**Key Points:**
- `strict: true` catches most errors
- Set `target` based on your Node.js version
- Use `outDir` and `rootDir` to organize build output
- Path aliases make imports cleaner

---

### 5. Express - Basic Server Setup

**What it is:** Express is a minimal web framework for Node.js that handles HTTP requests and responses.

**When to use:** Building REST APIs or web servers.

```typescript
// src/server.ts
import express, { Application, Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app: Application = express();
const PORT = process.env.PORT || 5000;

// Built-in Middleware
app.use(express.json());                    // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Basic Route
app.get('/', (req: Request, res: Response) => {
  res.json({ message: 'API is running' });
});

// Route with parameters
app.get('/users/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  res.json({ userId: id });
});

// Route with query parameters
// GET /search?q=typescript&limit=10
app.get('/search', (req: Request, res: Response) => {
  const { q, limit } = req.query;
  res.json({ query: q, limit: limit || 10 });
});

// POST route
app.post('/users', (req: Request, res: Response) => {
  const userData = req.body;
  res.status(201).json({ 
    message: 'User created',
    data: userData 
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;
```

**Key Points:**
- `express.json()` is required to parse JSON request bodies
- Use proper HTTP methods: GET (read), POST (create), PUT (update), DELETE (remove)
- Status codes matter: 200 (OK), 201 (Created), 400 (Bad Request), 500 (Server Error)

---

### 6. Express - Route Organization (MVC Pattern)

**What it is:** Separating concerns into Models, Views, and Controllers for better code organization.

**When to use:** Any Express application beyond a simple prototype.

```typescript
// src/routes/userRoutes.ts
import express, { Router } from 'express';
import { 
  getUsers, 
  getUserById, 
  createUser, 
  updateUser, 
  deleteUser 
} from '../controllers/userController';
import { authMiddleware } from '../middleware/auth';

const router: Router = express.Router();

// Public routes
router.post('/register', createUser);

// Protected routes (require authentication)
router.use(authMiddleware); // Applied to all routes below
router.get('/', getUsers);
router.get('/:id', getUserById);
router.put('/:id', updateUser);
router.delete('/:id', deleteUser);

export default router;

// src/controllers/userController.ts
import { Request, Response, NextFunction } from 'express';
import User from '../models/User';

export const getUsers = async (
  req: Request, 
  res: Response, 
  next: NextFunction
) => {
  try {
    const users = await User.find().select('-password');
    res.json({ success: true, data: users });
  } catch (error) {
    next(error); // Pass to error handler
  }
};

export const getUserById = async (
  req: Request, 
  res: Response, 
  next: NextFunction
) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    res.json({ success: true, data: user });
  } catch (error) {
    next(error);
  }
};

export const createUser = async (
  req: Request, 
  res: Response, 
  next: NextFunction
) => {
  try {
    const user = await User.create(req.body);
    res.status(201).json({ success: true, data: user });
  } catch (error) {
    next(error);
  }
};

// src/server.ts - Connecting routes
import userRoutes from './routes/userRoutes';

app.use('/api/users', userRoutes);
```

**Project Structure:**
```
src/
├── controllers/     # Business logic
├── routes/          # Route definitions
├── models/          # Database models
├── middleware/      # Custom middleware
├── utils/           # Helper functions
└── server.ts        # Entry point
```

**Key Points:**
- Controllers handle business logic
- Routes define endpoints and use controllers
- Keep routes file clean and focused
- Use `next(error)` to pass errors to error handler

---

### 7. Middleware - Understanding Middleware

**What it is:** Functions that have access to request, response, and next function. They execute in order.

**When to use:** For cross-cutting concerns like authentication, logging, validation.

```typescript
// Middleware signature
import { Request, Response, NextFunction } from 'express';

// Basic middleware structure
const myMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // Do something
  console.log('Middleware executed');
  next(); // Pass control to next middleware
};

// Logging middleware
const logger = (req: Request, res: Response, next: NextFunction) => {
  console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
  next();
};

// Request timing middleware
const requestTimer = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  
  // Execute after response is sent
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`Request took ${duration}ms`);
  });
  
  next();
};

// Application-level middleware (runs for all routes)
app.use(logger);

// Router-level middleware (runs for specific routes)
const router = express.Router();
router.use(authMiddleware);
router.get('/protected', (req, res) => {
  res.json({ message: 'Protected route' });
});

// Route-specific middleware
app.get('/admin', 
  authMiddleware, 
  roleMiddleware(['admin']), 
  (req, res) => {
    res.json({ message: 'Admin only' });
  }
);

// Error-handling middleware (must have 4 parameters)
const errorHandler = (
  err: Error, 
  req: Request, 
  res: Response, 
  next: NextFunction
) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: err.message 
  });
};

// Must be last
app.use(errorHandler);
```

**Middleware Flow:**
```
Request → Middleware 1 → Middleware 2 → Route Handler → Response
          (next())       (next())         (res.json())
```

**Key Points:**
- Always call `next()` unless you're ending the request
- Order matters - middleware executes sequentially
- Error middleware must have 4 parameters
- Use `next(error)` to pass errors to error handler

---

### 8. Middleware - Third-Party Security Middleware

**What it is:** Pre-built middleware packages that add security features.

**When to use:** Every production Express application.

```typescript
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

const app = express();

// Helmet - Sets security-related HTTP headers
app.use(helmet());
// Adds headers like:
// - X-Content-Type-Options: nosniff
// - X-Frame-Options: DENY
// - X-XSS-Protection: 1; mode=block

// CORS - Control which domains can access your API
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true, // Allow cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Morgan - HTTP request logger
app.use(morgan('combined')); // Logs: IP, method, URL, status, response time

// Rate Limiting - Prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false,
});

// Apply to all routes
app.use('/api/', limiter);

// Stricter limit for authentication routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Only 5 attempts per 15 minutes
  skipSuccessfulRequests: true, // Don't count successful requests
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Body size limiting (prevent large payloads)
app.use(express.json({ limit: '10kb' }));
```

**Security Headers Example:**
```
X-DNS-Prefetch-Control: off
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Download-Options: noopen
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
```

**Key Points:**
- Helmet protects against common vulnerabilities
- CORS prevents unauthorized cross-origin requests
- Rate limiting stops brute force attacks
- Always set body size limits

---

### 9. Middleware - Custom Validation Middleware

**What it is:** Middleware that validates request data before it reaches your controller.

**When to use:** Every route that accepts user input.

```typescript
// Using Zod for validation
import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';

// Define validation schema
const createUserSchema = z.object({
  body: z.object({
    email: z.string().email('Invalid email format'),
    password: z.string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Password must contain uppercase letter')
      .regex(/[a-z]/, 'Password must contain lowercase letter')
      .regex(/[0-9]/, 'Password must contain number'),
    name: z.string().min(2, 'Name must be at least 2 characters'),
    role: z.enum(['user', 'admin', 'manager']).optional(),
  }),
});

// Validation middleware
const validate = (schema: z.ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      schema.parse({
        body: req.body,
        query: req.query,
        params: req.params,
      });
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          success: false,
          message: 'Validation error',
          errors: error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message,
          })),
        });
      }
      next(error);
    }
  };
};

// Usage in routes
import { validate } from '../middleware/validation';

router.post('/users', 
  validate(createUserSchema), 
  createUser
);

// Task validation example
const createTaskSchema = z.object({
  body: z.object({
    title: z.string().min(3).max(200),
    description: z.string().max(2000).optional(),
    status: z.enum(['todo', 'in_progress', 'review', 'done']),
    priority: z.enum(['low', 'medium', 'high']),
    assignedTo: z.string().optional(),
    dueDate: z.string().datetime().optional(),
  }),
});

// Query parameter validation
const getUsersSchema = z.object({
  query: z.object({
    page: z.string().regex(/^\d+$/).transform(Number).optional(),
    limit: z.string().regex(/^\d+$/).transform(Number).optional(),
    role: z.enum(['user', 'admin', 'manager']).optional(),
  }),
});

router.get('/users', 
  validate(getUsersSchema), 
  getUsers
);
```

**Key Points:**
- Validate early, before business logic
- Return clear error messages
- Validate body, query params, and URL params
- Use schema libraries (Zod, Joi) for complex validation

---

### 10. Error Handling Middleware

**What it is:** Centralized error handling for consistent error responses.

**When to use:** Every Express application needs this.

```typescript
// Custom error class
class AppError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true; // Operational errors (vs programming errors)
    Error.captureStackTrace(this, this.constructor);
  }
}

// Error handling middleware
const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Default to 500 server error
  let statusCode = 500;
  let message = 'Internal server error';
  let errors = undefined;

  // Handle custom AppError
  if (err instanceof AppError) {
    statusCode = err.statusCode;
    message = err.message;
  }

  // Handle Mongoose validation errors
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation error';
    errors = Object.values((err as any).errors).map((e: any) => e.message);
  }

  // Handle Mongoose cast errors (invalid ID)
  if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  }

  // Handle duplicate key errors (MongoDB)
  if ((err as any).code === 11000) {
    statusCode = 400;
    message = 'Duplicate field value';
    const field = Object.keys((err as any).keyPattern)[0];
    errors = [`${field} already exists`];
  }

  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
  }

  if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
  }

  // Log error in development
  if (process.env.NODE_ENV === 'development') {
    console.error('Error:', err);
  }

  // Send response
  res.status(statusCode).json({
    success: false,
    message,
    errors,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
};

// Usage in controllers
import { AppError } from '../utils/AppError';

export const getUserById = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      throw new AppError('User not found', 404);
    }
    
    res.json({ success: true, data: user });
  } catch (error) {
    next(error); // Pass to error handler
  }
};

// Async wrapper to avoid try-catch in every controller
const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Usage
export const getUsers = asyncHandler(async (req: Request, res: Response) => {
  const users = await User.find();
  res.json({ success: true, data: users });
  // No try-catch needed!
});

// In server.ts - must be last middleware
app.use(errorHandler);
```

**Key Points:**
- Centralize error handling for consistency
- Use custom error classes for operational errors
- Handle different error types appropriately
- Never expose stack traces in production
- Use `next(error)` to pass errors to handler

---

## Week 2: Authentication, Authorization & Database

### 11. Password Hashing with bcrypt

**What it is:** Secure one-way encryption of passwords using bcrypt algorithm.

**When to use:** Always when storing passwords. Never store plain text passwords.

```typescript
import bcrypt from 'bcryptjs';

// Hashing a password during registration
const hashPassword = async (plainPassword: string): Promise<string> => {
  const saltRounds = 10; // Higher = more secure but slower (10-12 is good)
  const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
  return hashedPassword;
};

// Example output:
// Input: "MyPassword123"
// Output: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// Comparing password during login
const comparePassword = async (
  plainPassword: string, 
  hashedPassword: string
): Promise<boolean> => {
  const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
  return isMatch;
};

// Usage in User model
import mongoose, { Document, Schema } from 'mongoose';

interface IUser extends Document {
  email: string;
  password: string;
  name: string;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 8 },
  name: { type: String, required: true },
}, { timestamps: true });

// Hash password before saving (pre-save hook)
userSchema.pre('save', async function(next) {
  // Only hash if password is modified
  if (!this.isModified('password')) {
    return next();
  }
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error: any) {
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(
  candidatePassword: string
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

// Never return password in JSON
userSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

const User = mongoose.model<IUser>('User', userSchema);

// Usage in controller
export const register = async (req: Request, res: Response) => {
  const { email, password, name } = req.body;
  
  // Password automatically hashed by pre-save hook
  const user = await User.create({ email, password, name });
  
  res.status(201).json({ 
    success: true, 
    data: user // password excluded by toJSON
  });
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email }).select('+password');
  
  if (!user || !(await user.comparePassword(password))) {
    throw new AppError('Invalid credentials', 401);
  }
  
  // Generate token...
};
```

**Key Points:**
- Never store plain text passwords
- Use salt rounds of 10-12
- Hash in pre-save hook for automatic hashing
- Use instance method for password comparison
- Exclude password from JSON responses

---

### 12. JWT (JSON Web Tokens) - Structure & Generation

**What it is:** Stateless authentication tokens containing encoded user information.

**When to use:** Modern API authentication, especially for SPAs and mobile apps.

```typescript
import jwt from 'jsonwebtoken';

// JWT Structure: header.payload.signature
// Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjMiLCJpYXQiOjE2MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

// Token payload (data stored in token)
interface TokenPayload {
  userId: string;
  email: string;
  role: string;
}

// Generate Access Token (short-lived)
const generateAccessToken = (payload: TokenPayload): string => {
  return jwt.sign(
    payload,
    process.env.JWT_ACCESS_SECRET!,
    { expiresIn: '15m' } // 15 minutes
  );
};

// Generate Refresh Token (long-lived)
const generateRefreshToken = (payload: TokenPayload): string => {
  return jwt.sign(
    payload,
    process.env.JWT_REFRESH_SECRET!,
    { expiresIn: '7d' } // 7 days
  );
};

// Verify Token
const verifyToken = (token: string, secret: string): TokenPayload => {
  try {
    const decoded = jwt.verify(token, secret) as TokenPayload;
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new AppError('Token expired', 401);
    }
    throw new AppError('Invalid token', 401);
  }
};

// Complete Authentication Flow
export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;
  
  // 1. Find user
  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.comparePassword(password))) {
    throw new AppError('Invalid credentials', 401);
  }
  
  // 2. Generate tokens
  const tokenPayload = {
    userId: user._id.toString(),
    email: user.email,
    role: user.role,
  };
  
  const accessToken = generateAccessToken(tokenPayload);
  const refreshToken = generateRefreshToken(tokenPayload);
  
  // 3. Store refresh token in database
  await RefreshToken.create({
    token: refreshToken,
    userId: user._id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
  });
  
  // 4. Send tokens
  // Option 1: httpOnly cookies (recommended - more secure)
  res.cookie('accessToken', accessToken, {
    httpOnly: true,  // Cannot be accessed by JavaScript
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict', // CSRF protection
    maxAge: 15 * 60 * 1000, // 15 minutes
  });
  
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
  
  // Option 2: Send in response body (less secure, but simpler)
  res.json({
    success: true,
    data: {
      user: user.toJSON(),
      accessToken,
      refreshToken,
    },
  });
};

// Refresh Token Endpoint
export const refreshAccessToken = async (req: Request, res: Response) => {
  const { refreshToken } = req.cookies || req.body;
  
  if (!refreshToken) {
    throw new AppError('Refresh token required', 401);
  }
  
  // 1. Verify refresh token
  const decoded = verifyToken(refreshToken, process.env.JWT_REFRESH_SECRET!);
  
  // 2. Check if token exists and not revoked in database
  const storedToken = await RefreshToken.findOne({
    token: refreshToken,
    userId: decoded.userId,
    isRevoked: false,
  });
  
  if (!storedToken) {
    throw new AppError('Invalid refresh token', 401);
  }
  
  // 3. Generate new access token
  const newAccessToken = generateAccessToken({
    userId: decoded.userId,
    email: decoded.email,
    role: decoded.role,
  });
  
  // 4. Optional: Rotate refresh token (more secure)
  const newRefreshToken = generateRefreshToken({
    userId: decoded.userId,
    email: decoded.email,
    role: decoded.role,
  });
  
  // Revoke old refresh token
  await RefreshToken.findByIdAndUpdate(storedToken._id, { isRevoked: true });
  
  // Store new refresh token
  await RefreshToken.create({
    token: newRefreshToken,
    userId: decoded.userId,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  
  res.json({
    success: true,
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  });
};

// Logout
export const logout = async (req: Request, res: Response) => {
  const { refreshToken } = req.cookies || req.body;
  
  if (refreshToken) {
    // Revoke refresh token
    await RefreshToken.updateOne(
      { token: refreshToken },
      { isRevoked: true }
    );
  }
  
  // Clear cookies
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  
  res.json({ success: true, message: 'Logged out successfully' });
};
```

**RefreshToken Model:**
```typescript
import mongoose, { Schema, Document } from 'mongoose';

interface IRefreshToken extends Document {
  token: string;
  userId: mongoose.Types.ObjectId;
  expiresAt: Date;
  isRevoked: boolean;
}

const refreshTokenSchema = new Schema<IRefreshToken>({
  token: { type: String, required: true, unique: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true },
  isRevoked: { type: Boolean, default: false },
}, { timestamps: true });

// Auto-delete expired tokens (TTL index)
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model<IRefreshToken>('RefreshToken', refreshTokenSchema);
```

**Key Points:**
- Access tokens: short-lived (15 min), for API requests
- Refresh tokens: long-lived (7 days), to get new access tokens
- Store refresh tokens in database to allow revocation
- Use httpOnly cookies for better security
- Rotate refresh tokens on each use (optional but more secure)

---

### 13. Authentication Middleware

**What it is:** Middleware that verifies JWT tokens and protects routes.

**When to use:** Any route that requires authentication.

```typescript
// src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import { AppError } from '../utils/AppError';

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        role: string;
      };
    }
  }
}

export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // 1. Get token from header or cookie
    let token: string | undefined;
    
    // From Authorization header: "Bearer <token>"
    if (req.headers.authorization?.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // From cookie (if using httpOnly cookies)
    else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }
    
    if (!token) {
      throw new AppError('Not authenticated. Please log in.', 401);
    }
    
    // 2. Verify token
    const decoded = jwt.verify(
      token,
      process.env.JWT_ACCESS_SECRET!
    ) as { userId: string; email: string; role: string };
    
    // 3. Check if user still exists
    const user = await User.findById(decoded.userId);
    if (!user) {
      throw new AppError('User no longer exists', 401);
    }
    
    // 4. Check if user is active
    if (!user.isActive) {
      throw new AppError('Account is deactivated', 401);
    }
    
    // 5. Attach user to request
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
    };
    
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      next(new AppError('Invalid token', 401));
    } else if (error instanceof jwt.TokenExpiredError) {
      next(new AppError('Token expired', 401));
    } else {
      next(error);
    }
  }
};

// Optional: Middleware to check if already authenticated
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    let token: string | undefined;
    
    if (req.headers.authorization?.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }
    
    if (token) {
      const decoded = jwt.verify(
        token,
        process.env.JWT_ACCESS_SECRET!
      ) as { userId: string; email: string; role: string };
      
      req.user = decoded;
    }
    
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};

// Usage in routes
import { authMiddleware } from '../middleware/auth';

// Protect single route
router.get('/profile', authMiddleware, getProfile);

// Protect all routes in router
router.use(authMiddleware);
router.get('/dashboard', getDashboard);
router.get('/settings', getSettings);
```

**Key Points:**
- Extract token from Authorization header or cookies
- Verify token signature and expiration
- Check if user still exists and is active
- Attach user info to request object for use in controllers
- Handle different JWT errors appropriately

---

### 14. Role-Based Access Control (RBAC)

**What it is:** Authorization system that restricts access based on user roles.

**When to use:** When different users need different levels of access.

```typescript
// src/middleware/roleCheck.ts
import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/AppError';

type Role = 'user' | 'manager' | 'admin';

// Middleware to check if user has required role
export const requireRole = (allowedRoles: Role[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new AppError('Not authenticated', 401);
    }
    
    if (!allowedRoles.includes(req.user.role as Role)) {
      throw new AppError(
        'You do not have permission to perform this action',
        403 // Forbidden
      );
    }
    
    next();
  };
};

// Alternative: Role hierarchy (each role includes lower roles)
const roleHierarchy: Record<Role, number> = {
  user: 1,
  manager: 2,
  admin: 3,
};

export const requireMinRole = (minRole: Role) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new AppError('Not authenticated', 401);
    }
    
    const userRoleLevel = roleHierarchy[req.user.role as Role] || 0;
    const requiredRoleLevel = roleHierarchy[minRole];
    
    if (userRoleLevel < requiredRoleLevel) {
      throw new AppError(
        'Insufficient permissions',
        403
      );
    }
    
    next();
  };
};

// Usage in routes
import { authMiddleware } from '../middleware/auth';
import { requireRole, requireMinRole } from '../middleware/roleCheck';

// Only admins can access
router.delete('/users/:id',
  authMiddleware,
  requireRole(['admin']),
  deleteUser
);

// Admins and managers can access
router.post('/teams',
  authMiddleware,
  requireRole(['admin', 'manager']),
  createTeam
);

// Using hierarchy (manager and above)
router.get('/reports',
  authMiddleware,
  requireMinRole('manager'),
  getReports
);

// Multiple middlewares
router.put('/tasks/:id',
  authMiddleware,
  requireRole(['admin', 'manager']),
  validateTask,
  updateTask
);
```

**Resource Ownership Check:**
```typescript
// Middleware to check if user owns the resource
export const requireOwnership = (model: any) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const resourceId = req.params.id;
      const resource = await model.findById(resourceId);
      
      if (!resource) {
        throw new AppError('Resource not found', 404);
      }
      
      // Check if user is owner or admin
      const isOwner = resource.createdBy?.toString() === req.user?.userId;
      const isAdmin = req.user?.role === 'admin';
      
      if (!isOwner && !isAdmin) {
        throw new AppError('You can only modify your own resources', 403);
      }
      
      // Attach resource to request for use in controller
      req.resource = resource;
      next();
    } catch (error) {
      next(error);
    }
  };
};

// Usage
router.delete('/tasks/:id',
  authMiddleware,
  requireOwnership(Task),
  deleteTask
);

// In controller
export const deleteTask = async (req: Request, res: Response) => {
  // Resource already loaded by middleware
  await req.resource.remove();
  res.json({ success: true, message: 'Task deleted' });
};
```

**Permission-Based System (more granular):**
```typescript
// Define permissions
enum Permission {
  CREATE_USER = 'create:user',
  READ_USER = 'read:user',
  UPDATE_USER = 'update:user',
  DELETE_USER = 'delete:user',
  MANAGE_TEAM = 'manage:team',
  VIEW_REPORTS = 'view:reports',
}

// Role permissions mapping
const rolePermissions: Record<Role, Permission[]> = {
  user: [
    Permission.READ_USER,
    Permission.UPDATE_USER,
  ],
  manager: [
    Permission.READ_USER,
    Permission.UPDATE_USER,
    Permission.MANAGE_TEAM,
    Permission.VIEW_REPORTS,
  ],
  admin: Object.values(Permission), // All permissions
};

// Check permission middleware
export const requirePermission = (permission: Permission) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new AppError('Not authenticated', 401);
    }
    
    const userPermissions = rolePermissions[req.user.role as Role] || [];
    
    if (!userPermissions.includes(permission)) {
      throw new AppError('Insufficient permissions', 403);
    }
    
    next();
  };
};

// Usage
router.delete('/users/:id',
  authMiddleware,
  requirePermission(Permission.DELETE_USER),
  deleteUser
);
```

**Key Points:**
- 401 Unauthorized: Not authenticated (not logged in)
- 403 Forbidden: Authenticated but no permission
- Check authentication before authorization
- Consider role hierarchy vs discrete roles
- Implement resource ownership checks
- Permissions offer more granular control than roles

---

### 15. MongoDB & Mongoose Setup

**What it is:** MongoDB is a NoSQL database, Mongoose is an ODM (Object Document Mapper) for MongoDB.

**When to use:** When you need flexible schema and scalable document storage.

```typescript
// src/config/database.ts
import mongoose from 'mongoose';

export const connectDatabase = async (): Promise<void> => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI!, {
      // Options (most are default in Mongoose 6+)
      // No need for useNewUrlParser, useUnifiedTopology, etc.
    });
    
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    
    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected');
    });
    
    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('MongoDB connection closed');
      process.exit(0);
    });
    
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1);
  }
};

// src/server.ts
import { connectDatabase } from './config/database';

const startServer = async () => {
  await connectDatabase();
  
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
};

startServer();
```

**Environment Variables (.env):**
```
# Local MongoDB
MONGODB_URI=mongodb://localhost:27017/taskmanager

# MongoDB Atlas (cloud)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/taskmanager?retryWrites=true&w=majority
```

**Key Points:**
- Always use environment variables for connection strings
- Handle connection errors gracefully
- Close connection on application shutdown
- Use MongoDB Atlas for cloud hosting

---

### 16. Mongoose Schemas & Models

**What it is:** Schemas define the structure of documents, Models are constructors for documents.

**When to use:** For every collection in your MongoDB database.

```typescript
// src/models/Task.ts
import mongoose, { Schema, Document, Types } from 'mongoose';

// TypeScript interface for type safety
export interface ITask extends Document {
  title: string;
  description?: string;
  status: 'todo' | 'in_progress' | 'review' | 'done';
  priority: 'low' | 'medium' | 'high';
  assignedTo?: Types.ObjectId;
  teamId?: Types.ObjectId;
  createdBy: Types.ObjectId;
  dueDate?: Date;
  tags: string[];
  attachments: {
    filename: string;
    url: string;
    uploadedAt: Date;
  }[];
  completedAt?: Date;
  isArchived: boolean;
}

const taskSchema = new Schema<ITask>({
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    minlength: [3, 'Title must be at least 3 characters'],
    maxlength: [200, 'Title cannot exceed 200 characters'],
  },
  description: {
    type: String,
    trim: true,
    maxlength: [2000, 'Description cannot exceed 2000 characters'],
  },
  status: {
    type: String,
    enum: {
      values: ['todo', 'in_progress', 'review', 'done'],
      message: '{VALUE} is not a valid status',
    },
    default: 'todo',
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium',
  },
  assignedTo: {
    type: Schema.Types.ObjectId,
    ref: 'User', // Reference to User model
  },
  teamId: {
    type: Schema.Types.ObjectId,
    ref: 'Team',
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  dueDate: {
    type: Date,
    validate: {
      validator: function(value: Date) {
        return value > new Date();
      },
      message: 'Due date must be in the future',
    },
  },
  tags: [{
    type: String,
    trim: true,
  }],
  attachments: [{
    filename: String,
    url: String,
    uploadedAt: { type: Date, default: Date.now },
  }],
  completedAt: Date,
  isArchived: {
    type: Boolean,
    default: false,
  },
}, {
  timestamps: true, // Adds createdAt and updatedAt automatically
  toJSON: { virtuals: true }, // Include virtuals in JSON
  toObject: { virtuals: true },
});

// Indexes for better query performance
taskSchema.index({ status: 1, priority: 1 }); // Compound index
taskSchema.index({ assignedTo: 1 });
taskSchema.index({ teamId: 1 });
taskSchema.index({ createdBy: 1 });
taskSchema.index({ dueDate: 1 });
taskSchema.index({ title: 'text', description: 'text' }); // Text search

// Virtual property (not stored in DB)
taskSchema.virtual('isOverdue').get(function() {
  if (this.status === 'done' || !this.dueDate) return false;
  return this.dueDate < new Date();
});

// Instance method
taskSchema.methods.markAsComplete = function() {
  this.status = 'done';
  this.completedAt = new Date();
  return this.save();
};

// Static method
taskSchema.statics.findOverdueTasks = function() {
  return this.find({
    status: { $ne: 'done' },
    dueDate: { $lt: new Date() },
  });
};

// Pre-save hook
taskSchema.pre('save', function(next) {
  // Auto-set completedAt when status changes to done
  if (this.isModified('status') && this.status === 'done') {
    this.completedAt = new Date();
  }
  next();
});

// Pre-delete hook
taskSchema.pre('remove', async function(next) {
  // Clean up related data
  console.log(`Cleaning up task ${this._id}`);
  next();
});

const Task = mongoose.model<ITask>('Task', taskSchema);
export default Task;
```

**Using the Model:**
```typescript
// Create
const task = await Task.create({
  title: 'Build API',
  description: 'Create REST API with Express',
  priority: 'high',
  createdBy: userId,
});

// Find
const tasks = await Task.find({ status: 'todo' });
const task = await Task.findById(taskId);
const task = await Task.findOne({ title: 'Build API' });

// Update
const task = await Task.findByIdAndUpdate(
  taskId,
  { status: 'done' },
  { new: true, runValidators: true } // Return updated doc, run validators
);

// Delete
await Task.findByIdAndDelete(taskId);
await Task.deleteMany({ isArchived: true });

// Using instance methods
const task = await Task.findById(taskId);
await task.markAsComplete();

// Using static methods
const overdueTasks = await Task.findOverdueTasks();

// Population (load referenced documents)
const task = await Task.findById(taskId)
  .populate('assignedTo', 'name email') // Only include name and email
  .populate('createdBy');
```

**Key Points:**
- Use TypeScript interfaces for type safety
- Add validation in schema definition
- Use indexes for frequently queried fields
- Virtuals for computed properties
- Hooks for automatic actions
- Instance methods for document-specific logic
- Static methods for model-level queries

---

### 17. Mongoose - Population & References

**What it is:** Loading related documents from other collections.

**When to use:** When you need to display related data (like user info with a task).

```typescript
// Models with references
const taskSchema = new Schema({
  title: String,
  assignedTo: {
    type: Schema.Types.ObjectId,
    ref: 'User', // References User model
  },
  teamId: {
    type: Schema.Types.ObjectId,
    ref: 'Team',
  },
  comments: [{
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User',
    },
    text: String,
    createdAt: Date,
  }],
});

// Basic population
const task = await Task.findById(taskId)
  .populate('assignedTo'); // Loads full user document

// Result:
// {
//   title: 'Build API',
//   assignedTo: {
//     _id: '507f1f77bcf86cd799439011',
//     name: 'John Doe',
//     email: 'john@example.com'
//   }
// }

// Select specific fields
const task = await Task.findById(taskId)
  .populate('assignedTo', 'name email'); // Only name and email

// Multiple populations
const task = await Task.findById(taskId)
  .populate('assignedTo', 'name email')
  .populate('teamId', 'name')
  .populate('comments.user', 'name avatar');

// Nested population
const task = await Task.findById(taskId)
  .populate({
    path: 'teamId',
    select: 'name members',
    populate: {
      path: 'members',
      select: 'name email',
    },
  });

// Conditional population
const task = await Task.findById(taskId)
  .populate({
    path: 'assignedTo',
    match: { isActive: true }, // Only populate if user is active
    select: 'name email',
  });

// Population in controllers
export const getTasks = async (req: Request, res: Response) => {
  const tasks = await Task.find()
    .populate('assignedTo', 'name email avatar')
    .populate('createdBy', 'name')
    .sort({ createdAt: -1 })
    .limit(20);
  
  res.json({ success: true, data: tasks });
};

// Virtual populate (reverse population)
const teamSchema = new Schema({
  name: String,
  members: [{ type: Schema.Types.ObjectId, ref: 'User' }],
});

// Virtual field for tasks (not stored in DB)
teamSchema.virtual('tasks', {
  ref: 'Task',
  localField: '_id',
  foreignField: 'teamId',
});

const team = await Team.findById(teamId)
  .populate('tasks'); // Gets all tasks for this team
```

**Key Points:**
- Use populate to load referenced documents
- Select only needed fields to reduce payload
- Can populate nested references
- Virtual populate for reverse relationships
- Be careful with over-population (performance impact)

---

### 18. Data Encryption & Sensitive Fields

**What it is:** Protecting sensitive data at rest using encryption.

**When to use:** For PII (Personally Identifiable Information), financial data, health records.

```typescript
import crypto from 'crypto';

// Encryption utility
class EncryptionService {
  private algorithm = 'aes-256-gcm';
  private key: Buffer;
  
  constructor() {
    // Key should be 32 bytes for aes-256
    const secret = process.env.ENCRYPTION_KEY!;
    this.key = crypto.scryptSync(secret, 'salt', 32);
  }
  
  encrypt(text: string): string {
    const iv = crypto.randomBytes(16); // Initialization vector
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Return: iv:authTag:encryptedData
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }
  
  decrypt(encryptedText: string): string {
    const [ivHex, authTagHex, encrypted] = encryptedText.split(':');
    
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}

const encryptionService = new EncryptionService();

// User model with encrypted fields
interface IUser extends Document {
  email: string;
  name: string;
  ssn?: string; // Social Security Number (encrypted)
  phoneNumber?: string; // Encrypted
  dateOfBirth?: Date;
  encryptField(field: string, value: string): string;
  decryptField(field: string): string;
}

const userSchema = new Schema<IUser>({
  email: { type: String, required: true },
  name: { type: String, required: true },
  ssn: { type: String, select: false }, // Not included by default
  phoneNumber: { type: String, select: false },
  dateOfBirth: Date,
});

// Encrypt before saving
userSchema.pre('save', function(next) {
  if (this.isModified('ssn') && this.ssn) {
    this.ssn = encryptionService.encrypt(this.ssn);
  }
  if (this.isModified('phoneNumber') && this.phoneNumber) {
    this.phoneNumber = encryptionService.encrypt(this.phoneNumber);
  }
  next();
});

// Helper methods
userSchema.methods.encryptField = function(field: string, value: string) {
  return encryptionService.encrypt(value);
};

userSchema.methods.decryptField = function(field: string) {
  const encryptedValue = this[field];
  if (!encryptedValue) return null;
  return encryptionService.decrypt(encryptedValue);
};

// Virtual for decrypted SSN
userSchema.virtual('ssnDecrypted').get(function() {
  if (!this.ssn) return null;
  return encryptionService.decrypt(this.ssn);
});

// Usage in controller
export const getUserProfile = async (req: Request, res: Response) => {
  // Must explicitly select encrypted fields
  const user = await User.findById(req.user?.userId)
    .select('+ssn +phoneNumber');
  
  if (!user) {
    throw new AppError('User not found', 404);
  }
  
  // Decrypt sensitive fields before sending
  const userData = {
    ...user.toObject(),
    ssn: user.ssnDecrypted, // Virtual property
    phoneNumber: user.decryptField('phoneNumber'),
  };
  
  res.json({ success: true, data: userData });
};

// Create user with encryption
export const createUser = async (req: Request, res: Response) => {
  const { email, name, ssn, phoneNumber } = req.body;
  
  // Encryption happens automatically in pre-save hook
  const user = await User.create({
    email,
    name,
    ssn, // Will be encrypted
    phoneNumber, // Will be encrypted
  });
  
  res.status(201).json({ success: true, data: user });
};
```

**Environment Variable:**
```
# .env
ENCRYPTION_KEY=your-32-character-secret-key-here-must-be-kept-safe
```

**Best Practices for Sensitive Data:**
```typescript
// 1. Don't log sensitive data
console.log(user); // Make sure password, SSN, etc are excluded

// 2. Exclude from JSON responses by default
userSchema.set('toJSON', {
  transform: function(doc, ret) {
    delete ret.password;
    delete ret.ssn;
    delete ret.phoneNumber;
    return ret;
  },
});

// 3. Use select: false for sensitive fields
const userSchema = new Schema({
  password: { type: String, required: true, select: false },
  ssn: { type: String, select: false },
});

// 4. Audit access to sensitive data
userSchema.post('findOne', async function(doc) {
  if (doc && this.getQuery()._id) {
    await AuditLog.create({
      action: 'USER_ACCESS',
      userId: doc._id,
      timestamp: new Date(),
      ipAddress: '...', // From request
    });
  }
});

// 5. Implement field-level permissions
const canAccessSensitiveData = (userRole: string): boolean => {
  return ['admin', 'hr'].includes(userRole);
};

export const getUserById = async (req: Request, res: Response) => {
  let selectFields = 'name email role';
  
  // Only certain roles can see sensitive data
  if (canAccessSensitiveData(req.user!.role)) {
    selectFields += ' ssn phoneNumber';
  }
  
  const user = await User.findById(req.params.id).select(selectFields);
  res.json({ success: true, data: user });
};
```

**Key Points:**
- Encrypt sensitive data before storing
- Use strong encryption algorithms (AES-256)
- Never log or expose encryption keys
- Exclude sensitive fields from default queries (`select: false`)
- Decrypt only when necessary
- Implement audit logging for sensitive data access
- Consider field-level access control
- Store encryption keys securely (use environment variables, never commit to git)

---

## Week 3: React with TypeScript & State Management

### 19. React with TypeScript - Component Typing

**What it is:** Using TypeScript to type React components, props, and state.

**When to use:** Always in React + TypeScript projects.

```typescript
// src/components/TaskCard.tsx
import React, { useState } from 'react';

// Props interface
interface TaskCardProps {
  id: string;
  title: string;
  description?: string; // Optional
  status: 'todo' | 'in_progress' | 'review' | 'done';
  priority: 'low' | 'medium' | 'high';
  assignedTo?: {
    id: string;
    name: string;
    avatar?: string;
  };
  onStatusChange: (taskId: string, newStatus: string) => void;
  onDelete: (taskId: string) => void;
  className?: string;
}

// Functional Component with Props
const TaskCard: React.FC<TaskCardProps> = ({
  id,
  title,
  description,
  status,
  priority,
  assignedTo,
  onStatusChange,
  onDelete,
  className = '',
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(false);

  const handleStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onStatusChange(id, e.target.value);
  };

  const handleDelete = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation();
    if (window.confirm('Are you sure you want to delete this task?')) {
      onDelete(id);
    }
  };

  return (
    <div className={`task-card ${className}`}>
      <h3>{title}</h3>
      {description && <p>{description}</p>}
      
      <select value={status} onChange={handleStatusChange}>
        <option value="todo">To Do</option>
        <option value="in_progress">In Progress</option>
        <option value="review">Review</option>
        <option value="done">Done</option>
      </select>

      {assignedTo && (
        <div className="assigned-to">
          {assignedTo.avatar && <img src={assignedTo.avatar} alt={assignedTo.name} />}
          <span>{assignedTo.name}</span>
        </div>
      )}

      <button onClick={handleDelete}>Delete</button>
    </div>
  );
};

export default TaskCard;

// Event Handler Types
const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
  console.log('Button clicked');
};

const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  console.log('Input changed:', e.target.value);
};

const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();
  console.log('Form submitted');
};

const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
  if (e.key === 'Enter') {
    console.log('Enter pressed');
  }
};

// Ref Types
import { useRef } from 'react';

const MyComponent: React.FC = () => {
  const inputRef = useRef<HTMLInputElement>(null);
  const divRef = useRef<HTMLDivElement>(null);

  const focusInput = () => {
    inputRef.current?.focus();
  };

  return (
    <div ref={divRef}>
      <input ref={inputRef} type="text" />
      <button onClick={focusInput}>Focus Input</button>
    </div>
  );
};

// Children Types
interface ContainerProps {
  children: React.ReactNode; // Any valid React child
  title: string;
}

const Container: React.FC<ContainerProps> = ({ children, title }) => {
  return (
    <div>
      <h2>{title}</h2>
      {children}
    </div>
  );
};

// Generic Component
interface ListProps<T> {
  items: T[];
  renderItem: (item: T, index: number) => React.ReactNode;
}

function List<T>({ items, renderItem }: ListProps<T>) {
  return (
    <ul>
      {items.map((item, index) => (
        <li key={index}>{renderItem(item, index)}</li>
      ))}
    </ul>
  );
}

// Usage
<List
  items={tasks}
  renderItem={(task, index) => <TaskCard {...task} />}
/>
```

**Key Points:**
- Use `React.FC<Props>` for functional components
- Type all props with interfaces
- Event handlers have specific types (MouseEvent, ChangeEvent, etc.)
- Use `React.ReactNode` for children
- Type refs with the HTML element type
- Optional props use `?`

---

### 20. Custom Hooks with TypeScript

**What it is:** Reusable logic extracted into custom hooks with proper typing.

**When to use:** When you have stateful logic that multiple components need.

```typescript
// src/hooks/useAuth.ts
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
}

interface UseAuthReturn {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  error: string | null;
}

export const useAuth = (): UseAuthReturn => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Check if user is logged in on mount
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const token = localStorage.getItem('accessToken');
      if (!token) {
        setIsLoading(false);
        return;
      }

      const response = await fetch('/api/auth/me', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
      } else {
        localStorage.removeItem('accessToken');
      }
    } catch (err) {
      console.error('Auth check failed:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string): Promise<void> => {
    try {
      setIsLoading(true);
      setError(null);

      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.message || 'Login failed');
      }

      const data = await response.json();
      localStorage.setItem('accessToken', data.accessToken);
      setUser(data.user);
      navigate('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      localStorage.removeItem('accessToken');
      setUser(null);
      navigate('/login');
    }
  };

  return {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    error,
  };
};

// src/hooks/useFetch.ts
import { useState, useEffect } from 'react';

interface UseFetchOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: any;
  headers?: Record<string, string>;
}

interface UseFetchReturn<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function useFetch<T>(
  url: string,
  options?: UseFetchOptions
): UseFetchReturn<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [refetchFlag, setRefetchFlag] = useState(0);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch(url, {
          method: options?.method || 'GET',
          headers: {
            'Content-Type': 'application/json',
            ...options?.headers,
          },
          body: options?.body ? JSON.stringify(options.body) : undefined,
        });

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        setData(result.data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [url, refetchFlag]);

  const refetch = () => setRefetchFlag(prev => prev + 1);

  return { data, loading, error, refetch };
}

// Usage
const TaskList: React.FC = () => {
  const { data: tasks, loading, error, refetch } = useFetch<Task[]>('/api/tasks');
  const { user, isAuthenticated } = useAuth();

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div>
      {tasks?.map(task => (
        <TaskCard key={task.id} {...task} />
      ))}
      <button onClick={refetch}>Refresh</button>
    </div>
  );
};

// src/hooks/useLocalStorage.ts
import { useState, useEffect } from 'react';

export function useLocalStorage<T>(
  key: string,
  initialValue: T
): [T, (value: T) => void] {
  // Get initial value from localStorage
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.error(error);
      return initialValue;
    }
  });

  // Update localStorage when value changes
  const setValue = (value: T) => {
    try {
      setStoredValue(value);
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.error(error);
    }
  };

  return [storedValue, setValue];
}

// Usage
const [theme, setTheme] = useLocalStorage<'light' | 'dark'>('theme', 'light');
```

**Key Points:**
- Always type the return value of custom hooks
- Use generics for reusable hooks
- Handle loading and error states
- Custom hooks must start with `use`
- Extract common logic into hooks

---

### 21. Redux Toolkit Setup

**What it is:** Modern Redux with less boilerplate and better TypeScript support.

**When to use:** For global state that many components need (auth, UI state).

```typescript
// src/store/store.ts
import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import uiReducer from './slices/uiSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    ui: uiReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: false, // If storing non-serializable data
    }),
});

// TypeScript types
export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

// src/store/hooks.ts
import { TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux';
import type { RootState, AppDispatch } from './store';

// Typed hooks
export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;

// src/store/slices/authSlice.ts
import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

const initialState: AuthState = {
  user: null,
  accessToken: localStorage.getItem('accessToken'),
  isAuthenticated: false,
  isLoading: false,
  error: null,
};

// Async thunk for login
export const loginUser = createAsyncThunk(
  'auth/login',
  async (credentials: { email: string; password: string }, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });

      if (!response.ok) {
        const error = await response.json();
        return rejectWithValue(error.message);
      }

      const data = await response.json();
      localStorage.setItem('accessToken', data.accessToken);
      return data;
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

// Async thunk for logout
export const logoutUser = createAsyncThunk(
  'auth/logout',
  async (_, { rejectWithValue }) => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      localStorage.removeItem('accessToken');
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

// Async thunk to get current user
export const getCurrentUser = createAsyncThunk(
  'auth/getCurrentUser',
  async (_, { rejectWithValue, getState }) => {
    try {
      const state = getState() as { auth: AuthState };
      const token = state.auth.accessToken;

      if (!token) {
        return rejectWithValue('No token found');
      }

      const response = await fetch('/api/auth/me', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to get user');
      }

      const data = await response.json();
      return data.user;
    } catch (error: any) {
      localStorage.removeItem('accessToken');
      return rejectWithValue(error.message);
    }
  }
);

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    // Synchronous actions
    setCredentials: (state, action: PayloadAction<{ user: User; accessToken: string }>) => {
      state.user = action.payload.user;
      state.accessToken = action.payload.accessToken;
      state.isAuthenticated = true;
    },
    clearAuth: (state) => {
      state.user = null;
      state.accessToken = null;
      state.isAuthenticated = false;
    },
    updateUser: (state, action: PayloadAction<Partial<User>>) => {
      if (state.user) {
        state.user = { ...state.user, ...action.payload };
      }
    },
  },
  extraReducers: (builder) => {
    // Login
    builder.addCase(loginUser.pending, (state) => {
      state.isLoading = true;
      state.error = null;
    });
    builder.addCase(loginUser.fulfilled, (state, action) => {
      state.isLoading = false;
      state.user = action.payload.user;
      state.accessToken = action.payload.accessToken;
      state.isAuthenticated = true;
    });
    builder.addCase(loginUser.rejected, (state, action) => {
      state.isLoading = false;
      state.error = action.payload as string;
    });

    // Logout
    builder.addCase(logoutUser.fulfilled, (state) => {
      state.user = null;
      state.accessToken = null;
      state.isAuthenticated = false;
    });

    // Get current user
    builder.addCase(getCurrentUser.pending, (state) => {
      state.isLoading = true;
    });
    builder.addCase(getCurrentUser.fulfilled, (state, action) => {
      state.isLoading = false;
      state.user = action.payload;
      state.isAuthenticated = true;
    });
    builder.addCase(getCurrentUser.rejected, (state) => {
      state.isLoading = false;
      state.user = null;
      state.accessToken = null;
      state.isAuthenticated = false;
    });
  },
});

export const { setCredentials, clearAuth, updateUser } = authSlice.actions;
export default authSlice.reducer;

// src/App.tsx - Provider setup
import { Provider } from 'react-redux';
import { store } from './store/store';

function App() {
  return (
    <Provider store={store}>
      {/* Your app */}
    </Provider>
  );
}

// Usage in components
import { useAppDispatch, useAppSelector } from './store/hooks';
import { loginUser, logoutUser } from './store/slices/authSlice';

const LoginPage: React.FC = () => {
  const dispatch = useAppDispatch();
  const { isLoading, error } = useAppSelector((state) => state.auth);

  const handleLogin = async (email: string, password: string) => {
    try {
      await dispatch(loginUser({ email, password })).unwrap();
      // Navigate to dashboard
    } catch (err) {
      console.error('Login failed:', err);
    }
  };

  return (
    <form onSubmit={(e) => {
      e.preventDefault();
      handleLogin('user@example.com', 'password');
    }}>
      {error && <div className="error">{error}</div>}
      {/* Form fields */}
      <button disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
};

const Header: React.FC = () => {
  const dispatch = useAppDispatch();
  const { user, isAuthenticated } = useAppSelector((state) => state.auth);

  const handleLogout = () => {
    dispatch(logoutUser());
  };

  return (
    <header>
      {isAuthenticated && user && (
        <>
          <span>Welcome, {user.name}</span>
          <button onClick={handleLogout}>Logout</button>
        </>
      )}
    </header>
  );
};
```

**Key Points:**
- Use `createSlice` for less boilerplate
- `createAsyncThunk` for async operations
- Type RootState and AppDispatch
- Create typed hooks (useAppDispatch, useAppSelector)
- Handle loading and error states in reducers
- Use `.unwrap()` on thunks to handle errors in components

---

### 22. React Query Setup & Usage

**What it is:** Library for fetching, caching, and updating server state in React.

**When to use:** For all server data (API calls). Don't use Redux for server state.

```typescript
// src/main.tsx or App.tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      {/* Your app */}
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  );
}

// src/api/tasks.ts - API functions
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('accessToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export interface Task {
  id: string;
  title: string;
  description: string;
  status: 'todo' | 'in_progress' | 'review' | 'done';
  priority: 'low' | 'medium' | 'high';
  assignedTo?: {
    id: string;
    name: string;
  };
}

export interface TaskCreateInput {
  title: string;
  description?: string;
  status: Task['status'];
  priority: Task['priority'];
  assignedTo?: string;
}

export const taskApi = {
  getTasks: async (filters?: { status?: string; priority?: string }): Promise<Task[]> => {
    const { data } = await api.get('/tasks', { params: filters });
    return data.data;
  },

  getTaskById: async (id: string): Promise<Task> => {
    const { data } = await api.get(`/tasks/${id}`);
    return data.data;
  },

  createTask: async (task: TaskCreateInput): Promise<Task> => {
    const { data } = await api.post('/tasks', task);
    return data.data;
  },

  updateTask: async (id: string, task: Partial<TaskCreateInput>): Promise<Task> => {
    const { data } = await api.put(`/tasks/${id}`, task);
    return data.data;
  },

  deleteTask: async (id: string): Promise<void> => {
    await api.delete(`/tasks/${id}`);
  },

  updateTaskStatus: async (id: string, status: Task['status']): Promise<Task> => {
    const { data } = await api.patch(`/tasks/${id}/status`, { status });
    return data.data;
  },
};

// src/hooks/useTasks.ts - React Query hooks
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { taskApi, Task, TaskCreateInput } from '../api/tasks';

// Query Keys
export const taskKeys = {
  all: ['tasks'] as const,
  lists: () => [...taskKeys.all, 'list'] as const,
  list: (filters: Record<string, any>) => [...taskKeys.lists(), filters] as const,
  details: () => [...taskKeys.all, 'detail'] as const,
  detail: (id: string) => [...taskKeys.details(), id] as const,
};

// Get all tasks
export const useTasks = (filters?: { status?: string; priority?: string }) => {
  return useQuery({
    queryKey: taskKeys.list(filters || {}),
    queryFn: () => taskApi.getTasks(filters),
  });
};

// Get single task
export const useTask = (id: string) => {
  return useQuery({
    queryKey: taskKeys.detail(id),
    queryFn: () => taskApi.getTaskById(id),
    enabled: !!id, // Only run if id exists
  });
};

// Create task mutation
export const useCreateTask = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (task: TaskCreateInput) => taskApi.createTask(task),
    onSuccess: () => {
      // Invalidate and refetch tasks
      queryClient.invalidateQueries({ queryKey: taskKeys.lists() });
    },
  });
};

// Update task mutation
export const useUpdateTask = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, task }: { id: string; task: Partial<TaskCreateInput> }) =>
      taskApi.updateTask(id, task),
    onSuccess: (data) => {
      // Update specific task in cache
      queryClient.setQueryData(taskKeys.detail(data.id), data);
      // Invalidate lists
      queryClient.invalidateQueries({ queryKey: taskKeys.lists() });
    },
  });
};

// Delete task mutation
export const useDeleteTask = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => taskApi.deleteTask(id),
    onSuccess: (_, deletedId) => {
      // Remove from cache
      queryClient.removeQueries({ queryKey: taskKeys.detail(deletedId) });
      // Invalidate lists
      queryClient.invalidateQueries({ queryKey: taskKeys.lists() });
    },
  });
};

// Update task status with optimistic update
export const useUpdateTaskStatus = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: Task['status'] }) =>
      taskApi.updateTaskStatus(id, status),
    onMutate: async ({ id, status }) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: taskKeys.detail(id) });

      // Snapshot previous value
      const previousTask = queryClient.getQueryData(taskKeys.detail(id));

      // Optimistically update
      queryClient.setQueryData(taskKeys.detail(id), (old: Task | undefined) =>
        old ? { ...old, status } : old
      );

      return { previousTask };
    },
    onError: (err, variables, context) => {
      // Rollback on error
      if (context?.previousTask) {
        queryClient.setQueryData(
          taskKeys.detail(variables.id),
          context.previousTask
        );
      }
    },
    onSettled: (data, error, variables) => {
      // Refetch after error or success
      queryClient.invalidateQueries({ queryKey: taskKeys.detail(variables.id) });
      queryClient.invalidateQueries({ queryKey: taskKeys.lists() });
    },
  });
};

// Usage in components
import { useTasks, useCreateTask, useDeleteTask, useUpdateTaskStatus } from './hooks/useTasks';

const TaskList: React.FC = () => {
  const [filter, setFilter] = useState<string>('all');
  
  const { data: tasks, isLoading, error, refetch } = useTasks(
    filter !== 'all' ? { status: filter } : undefined
  );
  
  const createMutation = useCreateTask();
  const deleteMutation = useDeleteTask();
  const updateStatusMutation = useUpdateTaskStatus();

  const handleCreate = async (taskData: TaskCreateInput) => {
    try {
      await createMutation.mutateAsync(taskData);
      alert('Task created successfully');
    } catch (error) {
      alert('Failed to create task');
    }
  };

  const handleDelete = (id: string) => {
    if (window.confirm('Are you sure?')) {
      deleteMutation.mutate(id);
    }
  };

  const handleStatusChange = (id: string, status: Task['status']) => {
    updateStatusMutation.mutate({ id, status });
  };

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;

  return (
    <div>
      <select value={filter} onChange={(e) => setFilter(e.target.value)}>
        <option value="all">All</option>
        <option value="todo">To Do</option>
        <option value="in_progress">In Progress</option>
        <option value="done">Done</option>
      </select>

      <button onClick={() => refetch()}>Refresh</button>

      {tasks?.map((task) => (
        <div key={task.id}>
          <h3>{task.title}</h3>
          <select
            value={task.status}
            onChange={(e) => handleStatusChange(task.id, e.target.value as Task['status'])}
          >
            <option value="todo">To Do</option>
            <option value="in_progress">In Progress</option>
            <option value="review">Review</option>
            <option value="done">Done</option>
          </select>
          <button onClick={() => handleDelete(task.id)}>Delete</button>
        </div>
      ))}
    </div>
  );
};
```

**Key Points:**
- React Query handles caching automatically
- Use queries for GET requests
- Use mutations for POST/PUT/DELETE
- Invalidate queries after mutations to refetch
- Optimistic updates for better UX
- DevTools for debugging
- Organize query keys for better cache management

---

### 23. Axios Interceptors & Token Refresh

**What it is:** Automatically add auth tokens and refresh expired tokens.

**When to use:** Every app with authentication.

```typescript
// src/api/axios.ts
import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000/api',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Send cookies
});

// Request interceptor - Add auth token
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem('accessToken');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error: AxiosError) => {
    return Promise.reject(error);
  }
);

// Response interceptor - Handle token refresh
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value?: any) => void;
  reject: (reason?: any) => void;
}> = [];

const processQueue = (error: Error | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // If error is 401 and we haven't retried yet
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // If already refreshing, queue this request
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${token}`;
            }
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Attempt to refresh token
        const refreshToken = localStorage.getItem('refreshToken');
        const response = await axios.post(
          `${process.env.REACT_APP_API_URL}/auth/refresh`,
          { refreshToken }
        );

        const { accessToken } = response.data;
        localStorage.setItem('accessToken', accessToken);

        // Update authorization header
        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
        }

        // Process queued requests
        processQueue(null, accessToken);

        // Retry original request
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh failed - logout user
        processQueue(new Error('Token refresh failed'), null);
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;

// Usage in API functions
import api from './axios';

export const taskApi = {
  getTasks: async () => {
    const { data } = await api.get('/tasks');
    return data.data;
  },
  
  createTask: async (taskData: any) => {
    const { data } = await api.post('/tasks', taskData);
    return data.data;
  },
};
```

**Key Points:**
- Automatically adds auth token to all requests
- Handles token refresh on 401 errors
- Queues failed requests during refresh
- Retries failed requests with new token
- Redirects to login if refresh fails
- Prevents multiple simultaneous refresh attempts

---

## Week 4: Frontend Security & Production

### 24. Protected Routes in React Router

**What it is:** Routes that require authentication to access.

**When to use:** Any route that needs login (dashboard, profile, etc.).

```typescript
// src/components/ProtectedRoute.tsx
import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAppSelector } from '../store/hooks';

interface ProtectedRouteProps {
  children?: React.ReactNode;
  redirectTo?: string;
}

// Basic protected route - requires authentication
export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  redirectTo = '/login' 
}) => {
  const { isAuthenticated, isLoading } = useAppSelector((state) => state.auth);
  const location = useLocation();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    // Redirect to login and save the attempted URL
    return <Navigate to={redirectTo} state={{ from: location }} replace />;
  }

  return children ? <>{children}</> : <Outlet />;
};

// src/components/PublicOnlyRoute.tsx
// Routes that only unauthenticated users can access (login, register)
export const PublicOnlyRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  redirectTo = '/dashboard' 
}) => {
  const { isAuthenticated, isLoading } = useAppSelector((state) => state.auth);
  const location = useLocation();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (isAuthenticated) {
    // If trying to access login while authenticated, redirect
    const from = (location.state as any)?.from?.pathname || redirectTo;
    return <Navigate to={from} replace />;
  }

  return children ? <>{children}</> : <Outlet />;
};

// src/components/RoleBasedRoute.tsx
interface RoleBasedRouteProps {
  allowedRoles: string[];
  children?: React.ReactNode;
  redirectTo?: string;
}

export const RoleBasedRoute: React.FC<RoleBasedRouteProps> = ({
  allowedRoles,
  children,
  redirectTo = '/unauthorized',
}) => {
  const { user, isAuthenticated, isLoading } = useAppSelector((state) => state.auth);
  const location = useLocation();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (!user || !allowedRoles.includes(user.role)) {
    return <Navigate to={redirectTo} replace />;
  }

  return children ? <>{children}</> : <Outlet />;
};

// src/App.tsx - Route configuration
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ProtectedRoute, PublicOnlyRoute, RoleBasedRoute } from './components/routes';

// Pages
import LoginPage from './pages/Login';
import RegisterPage from './pages/Register';
import DashboardPage from './pages/Dashboard';
import ProfilePage from './pages/Profile';
import TasksPage from './pages/Tasks';
import AdminPage from './pages/Admin';
import UnauthorizedPage from './pages/Unauthorized';
import NotFoundPage from './pages/NotFound';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes - only accessible when NOT logged in */}
        <Route element={<PublicOnlyRoute />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Route>

        {/* Protected routes - require authentication */}
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/tasks" element={<TasksPage />} />
          <Route path="/tasks/:id" element={<TaskDetailsPage />} />
        </Route>

        {/* Role-based routes */}
        <Route element={<RoleBasedRoute allowedRoles={['admin']} />}>
          <Route path="/admin" element={<AdminPage />} />
          <Route path="/admin/users" element={<UserManagementPage />} />
        </Route>

        <Route element={<RoleBasedRoute allowedRoles={['admin', 'manager']} />}>
          <Route path="/teams" element={<TeamsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
        </Route>

        {/* Other routes */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/unauthorized" element={<UnauthorizedPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;

// src/pages/Login.tsx - Login with redirect
import { useLocation, useNavigate } from 'react-router-dom';

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useAppDispatch();

  const handleLogin = async (email: string, password: string) => {
    try {
      await dispatch(loginUser({ email, password })).unwrap();
      
      // Redirect to originally attempted page or dashboard
      const from = (location.state as any)?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  return (
    <div>
      {/* Login form */}
    </div>
  );
};
```

**Conditional UI Rendering Based on Auth:**
```typescript
// src/components/Navbar.tsx
import { useAppSelector } from '../store/hooks';

const Navbar: React.FC = () => {
  const { user, isAuthenticated } = useAppSelector((state) => state.auth);

  return (
    <nav>
      <Link to="/">Home</Link>
      
      {isAuthenticated ? (
        <>
          <Link to="/dashboard">Dashboard</Link>
          <Link to="/tasks">Tasks</Link>
          
          {/* Show admin link only for admins */}
          {user?.role === 'admin' && (
            <Link to="/admin">Admin Panel</Link>
          )}
          
          {/* Show team management for managers and admins */}
          {(user?.role === 'admin' || user?.role === 'manager') && (
            <Link to="/teams">Teams</Link>
          )}
          
          <span>Welcome, {user?.name}</span>
          <button onClick={handleLogout}>Logout</button>
        </>
      ) : (
        <>
          <Link to="/login">Login</Link>
          <Link to="/register">Register</Link>
        </>
      )}
    </nav>
  );
};
```

**Key Points:**
- Always verify authentication on the backend too
- Save attempted URL to redirect after login
- Show/hide UI elements based on user role
- Use loading states while checking auth
- Public-only routes for login/register pages
- Role-based routes for admin/manager features

---

### 25. Secure Token Storage

**What it is:** Best practices for storing authentication tokens securely.

**When to use:** Every application with authentication.

```typescript
// ❌ BAD: Storing in localStorage (vulnerable to XSS)
localStorage.setItem('token', token); // Don't do this!

// ✅ GOOD: Using httpOnly cookies (set by backend)
// Backend sets cookie
res.cookie('accessToken', token, {
  httpOnly: true,  // Cannot be accessed by JavaScript
  secure: true,    // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 15 * 60 * 1000, // 15 minutes
});

// Frontend axios configuration to send cookies
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  withCredentials: true, // Send cookies with requests
});

// If you MUST use localStorage (less secure)
// src/utils/tokenStorage.ts
class TokenStorage {
  private readonly ACCESS_TOKEN_KEY = 'access_token';
  private readonly REFRESH_TOKEN_KEY = 'refresh_token';

  // Store tokens
  setTokens(accessToken: string, refreshToken: string): void {
    // Still vulnerable to XSS, but better than nothing
    try {
      localStorage.setItem(this.ACCESS_TOKEN_KEY, accessToken);
      // Store refresh token in a different storage
      sessionStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
    } catch (error) {
      console.error('Failed to store tokens:', error);
    }
  }

  getAccessToken(): string | null {
    return localStorage.getItem(this.ACCESS_TOKEN_KEY);
  }

  getRefreshToken(): string | null {
    return sessionStorage.getItem(this.REFRESH_TOKEN_KEY);
  }

  clearTokens(): void {
    localStorage.removeItem(this.ACCESS_TOKEN_KEY);
    sessionStorage.removeItem(this.REFRESH_TOKEN_KEY);
  }

  // Check if token is expired
  isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const exp = payload.exp * 1000; // Convert to milliseconds
      return Date.now() >= exp;
    } catch {
      return true;
    }
  }
}

export const tokenStorage = new TokenStorage();

// Using with Redux
import { tokenStorage } from '../utils/tokenStorage';

export const loginUser = createAsyncThunk(
  'auth/login',
  async (credentials: LoginCredentials) => {
    const response = await api.post('/auth/login', credentials);
    const { accessToken, refreshToken, user } = response.data;
    
    // Store tokens
    tokenStorage.setTokens(accessToken, refreshToken);
    
    return { user, accessToken };
  }
);

export const logoutUser = createAsyncThunk(
  'auth/logout',
  async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      tokenStorage.clearTokens();
    }
  }
);
```

**Security Best Practices:**
```typescript
// 1. Never log tokens
console.log(token); // ❌ Don't do this

// 2. Clear tokens on logout
const handleLogout = () => {
  tokenStorage.clearTokens();
  // Clear Redux state
  dispatch(clearAuth());
  // Redirect
  navigate('/login');
};

// 3. Check token expiration before requests
api.interceptors.request.use(async (config) => {
  const token = tokenStorage.getAccessToken();
  
  if (token && tokenStorage.isTokenExpired(token)) {
    // Try to refresh
    try {
      const newToken = await refreshAccessToken();
      config.headers.Authorization = `Bearer ${newToken}`;
    } catch {
      // Refresh failed, logout
      tokenStorage.clearTokens();
      window.location.href = '/login';
    }
  } else if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  
  return config;
});

// 4. Don't expose tokens in URLs
// ❌ Bad
navigate(`/verify?token=${token}`);

// ✅ Good - use state or POST request
navigate('/verify', { state: { token } });

// 5. Implement token rotation
const refreshAccessToken = async () => {
  const refreshToken = tokenStorage.getRefreshToken();
  const response = await api.post('/auth/refresh', { refreshToken });
  const { accessToken, refreshToken: newRefreshToken } = response.data;
  
  // Store new tokens
  tokenStorage.setTokens(accessToken, newRefreshToken);
  
  return accessToken;
};

// 6. Clear tokens on window close (for sensitive apps)
window.addEventListener('beforeunload', () => {
  // Only for highly sensitive applications
  tokenStorage.clearTokens();
});

// 7. Implement automatic logout on token expiration
import { useEffect } from 'react';

const useAutoLogout = () => {
  const dispatch = useAppDispatch();
  
  useEffect(() => {
    const checkTokenExpiration = () => {
      const token = tokenStorage.getAccessToken();
      if (token && tokenStorage.isTokenExpired(token)) {
        dispatch(logoutUser());
      }
    };
    
    // Check every minute
    const interval = setInterval(checkTokenExpiration, 60000);
    
    return () => clearInterval(interval);
  }, [dispatch]);
};

// Use in App component
function App() {
  useAutoLogout();
  
  return (
    // Your app
  );
}
```

**Comparison of Storage Methods:**

| Method | Security | XSS Vulnerable | CSRF Vulnerable | Persists |
|--------|----------|----------------|-----------------|----------|
| localStorage | Low | ✅ Yes | ❌ No | ✅ Yes |
| sessionStorage | Low | ✅ Yes | ❌ No | ❌ No |
| httpOnly Cookie | High | ❌ No | ✅ Yes* | ✅ Yes |
| Memory (State) | Medium | ❌ No | ❌ No | ❌ No |

*Use SameSite cookie attribute for CSRF protection

**Key Points:**
- httpOnly cookies are most secure
- If using localStorage, implement XSS protection
- Never log or expose tokens
- Implement token rotation
- Clear tokens on logout
- Check expiration before requests
- Use HTTPS in production

---

### 26. XSS Protection in React

**What it is:** Preventing Cross-Site Scripting attacks in React applications.

**When to use:** Always. Security is not optional.

```typescript
// React automatically escapes content
// This is SAFE
const UserProfile = ({ user }) => {
  return (
    <div>
      <h1>{user.name}</h1> {/* Safe - auto-escaped */}
      <p>{user.bio}</p>
    </div>
  );
};

// ❌ DANGEROUS: Using dangerouslySetInnerHTML
const UnsafeComponent = ({ content }) => {
  return (
    <div dangerouslySetInnerHTML={{ __html: content }} />
    // If content contains <script>alert('XSS')</script>, it will execute!
  );
};

// ✅ SAFE: Sanitize before using dangerouslySetInnerHTML
import DOMPurify from 'dompurify';

const SafeHTMLComponent: React.FC<{ content: string }> = ({ content }) => {
  const sanitizedContent = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'target'],
  });

  return (
    <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
  );
};

// ✅ BETTER: Use a markdown library instead
import ReactMarkdown from 'react-markdown';

const MarkdownComponent: React.FC<{ content: string }> = ({ content }) => {
  return <ReactMarkdown>{content}</ReactMarkdown>;
};

// Input sanitization utility
class InputSanitizer {
  // Remove HTML tags
  static stripHtml(input: string): string {
    return input.replace(/<[^>]*>/g, '');
  }

  // Escape HTML entities
  static escapeHtml(input: string): string {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
  }

  // Sanitize for use in URLs
  static sanitizeUrl(url: string): string {
    // Only allow http and https protocols
    const allowedProtocols = ['http:', 'https:'];
    try {
      const parsed = new URL(url);
      if (!allowedProtocols.includes(parsed.protocol)) {
        return '';
      }
      return url;
    } catch {
      return '';
    }
  }

  // Remove dangerous characters for SQL-like queries
  static sanitizeQuery(input: string): string {
    return input.replace(/['"`;]/g, '');
  }
}

// Usage in form
const CommentForm: React.FC = () => {
  const [comment, setComment] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // Sanitize input before sending to backend
    const sanitizedComment = InputSanitizer.stripHtml(comment);
    
    // Send to API
    createComment(sanitizedComment);
  };

  return (
    <form onSubmit={handleSubmit}>
      <textarea
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        maxLength={1000} // Limit input length
      />
      <button type="submit">Submit</button>
    </form>
  );
};

// Safe link component
interface SafeLinkProps {
  href: string;
  children: React.ReactNode;
  className?: string;
}

const SafeLink: React.FC<SafeLinkProps> = ({ href, children, className }) => {
  const safeHref = InputSanitizer.sanitizeUrl(href);
  
  if (!safeHref) {
    return <span className={className}>{children}</span>;
  }

  return (
    <a
      href={safeHref}
      className={className}
      target="_blank"
      rel="noopener noreferrer" // Prevent tabnabbing
    >
      {children}
    </a>
  );
};

// Content Security Policy (CSP) - Add to index.html
// <meta http-equiv="Content-Security-Policy" 
//       content="default-src 'self'; 
//                script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com;
//                style-src 'self' 'unsafe-inline';
//                img-src 'self' data: https:;
//                font-src 'self' data:;
//                connect-src 'self' http://localhost:5000;">

// Secure cookie handling
const setCookie = (name: string, value: string, days: number) => {
  const expires = new Date();
  expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
  
  document.cookie = `${name}=${value}; expires=${expires.toUTCString()}; path=/; Secure; SameSite=Strict`;
};

// Validate user input
const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password: string): { valid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain uppercase letter');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain lowercase letter');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain number');
  }
  if (!/[!@#$%^&*]/.test(password)) {
    errors.push('Password must contain special character');
  }
  
  return {
    valid: errors.length === 0,
    errors,
  };
};
```

**XSS Prevention Checklist:**
```typescript
// ✅ Security Checklist
const securityChecklist = {
  // 1. Never use dangerouslySetInnerHTML without sanitization
  useDangerouslySetInnerHTML: false,
  
  // 2. Sanitize all user input before displaying
  sanitizeUserInput: true,
  
  // 3. Use Content Security Policy headers
  useCSP: true,
  
  // 4. Validate input on both client and server
  validateInput: true,
  
  // 5. Escape user content in APIs
  escapeUserContent: true,
  
  // 6. Use rel="noopener noreferrer" for external links
  useSafeLinks: true,
  
  // 7. Limit input length
  limitInputLength: true,
  
  // 8. Use HTTPS only
  useHTTPS: true,
  
  // 9. Set secure cookie flags
  useSecureCookies: true,
  
  // 10. Keep dependencies updated
  updateDependencies: true,
};
```

**Key Points:**
- React auto-escapes content (safe by default)
- Sanitize HTML before using dangerouslySetInnerHTML
- Use DOMPurify for HTML sanitization
- Validate all user input
- Use CSP headers
- Never trust user input
- Keep libraries updated

---

### 27. Environment Variables & Config

**What it is:** Managing configuration for different environments (dev, staging, production).

**When to use:** Always. Never hardcode API URLs or secrets.

```typescript
// .env.development
REACT_APP_API_URL=http://localhost:5000/api
REACT_APP_ENV=development
REACT_APP_ENABLE_LOGGING=true

// .env.production
REACT_APP_API_URL=https://api.production.com/api
REACT_APP_ENV=production
REACT_APP_ENABLE_LOGGING=false

// .env.local (not committed to git - add to .gitignore)
REACT_APP_API_KEY=your-secret-api-key

// src/config/env.ts
interface EnvConfig {
  apiUrl: string;
  environment: 'development' | 'staging' | 'production';
  enableLogging: boolean;
  apiKey?: string;
}

class EnvironmentConfig {
  private config: EnvConfig;

  constructor() {
    this.config = {
      apiUrl: process.env.REACT_APP_API_URL || 'http://localhost:5000/api',
      environment: (process.env.REACT_APP_ENV as any) || 'development',
      enableLogging: process.env.REACT_APP_ENABLE_LOGGING === 'true',
      apiKey: process.env.REACT_APP_API_KEY,
    };

    this.validate();
  }

  private validate(): void {
    if (!this.config.apiUrl) {
      throw new Error('REACT_APP_API_URL is required');
    }

    if (this.config.environment === 'production' && !this.config.apiKey) {
      console.warn('API key not configured for production');
    }
  }

  get apiUrl(): string {
    return this.config.apiUrl;
  }

  get environment(): string {
    return this.config.environment;
  }

  get isDevelopment(): boolean {
    return this.config.environment === 'development';
  }

  get isProduction(): boolean {
    return this.config.environment === 'production';
  }

  get enableLogging(): boolean {
    return this.config.enableLogging;
  }

  get apiKey(): string | undefined {
    return this.config.apiKey;
  }
}

export const env = new EnvironmentConfig();

// Usage
import { env } from './config/env';
import axios from 'axios';

const api = axios.create({
  baseURL: env.apiUrl,
});

// Conditional logging
const logger = {
  log: (...args: any[]) => {
    if (env.enableLogging) {
      console.log(...args);
    }
  },
  error: (...args: any[]) => {
    if (env.enableLogging) {
      console.error(...args);
    }
  },
};

// Feature flags based on environment
const features = {
  enableAnalytics: env.isProduction,
  enableDebugTools: env.isDevelopment,
  enableBetaFeatures: !env.isProduction,
};

// .gitignore
node_modules/
build/
.env.local
.env.*.local

// package.json scripts
{
  "scripts": {
    "start": "react-scripts start", // Uses .env.development
    "build": "react-scripts build",  // Uses .env.production
    "build:staging": "env-cmd -f .env.staging react-scripts build"
  }
}
```

**Backend Environment Variables:**
```typescript
// .env
NODE_ENV=development
PORT=5000
MONGODB_URI=mongodb://localhost:27017/taskmanager
JWT_ACCESS_SECRET=your-super-secret-access-key-change-this
JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-this
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d
FRONTEND_URL=http://localhost:3000
ENCRYPTION_KEY=your-32-character-encryption-key

// src/config/index.ts
import dotenv from 'dotenv';

dotenv.config();

interface Config {
  port: number;
  mongoUri: string;
  jwtAccessSecret: string;
  jwtRefreshSecret: string;
  jwtAccessExpiry: string;
  jwtRefreshExpiry: string;
  frontendUrl: string;
  encryptionKey: string;
  nodeEnv: string;
  isDevelopment: boolean;
  isProduction: boolean;
}

class ConfigService {
  private config: Config;

  constructor() {
    this.config = {
      port: parseInt(process.env.PORT || '5000', 10),
      mongoUri: process.env.MONGODB_URI!,
      jwtAccessSecret: process.env.JWT_ACCESS_SECRET!,
      jwtRefreshSecret: process.env.JWT_REFRESH_SECRET!,
      jwtAccessExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
      jwtRefreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
      frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
      encryptionKey: process.env.ENCRYPTION_KEY!,
      nodeEnv: process.env.NODE_ENV || 'development',
      isDevelopment: process.env.NODE_ENV === 'development',
      isProduction: process.env.NODE_ENV === 'production',
    };

    this.validateConfig();
  }

  private validateConfig(): void {
    const required = [
      'mongoUri',
      'jwtAccessSecret',
      'jwtRefreshSecret',
      'encryptionKey',
    ];

    for (const key of required) {
      if (!this.config[key as keyof Config]) {
        throw new Error(`Missing required environment variable: ${key.toUpperCase()}`);
      }
    }

    // Validate key lengths
    if (this.config.jwtAccessSecret.length < 32) {
      throw new Error('JWT_ACCESS_SECRET must be at least 32 characters');
    }

    if (this.config.encryptionKey.length !== 32) {
      throw new Error('ENCRYPTION_KEY must be exactly 32 characters');
    }
  }

  get<K extends keyof Config>(key: K): Config[K] {
    return this.config[key];
  }
}

export const config = new ConfigService();

// Usage
import { config } from './config';

const PORT = config.get('port');
const MONGO_URI = config.get('mongoUri');
```

**Key Points:**
- Never commit .env files to git
- Use different .env files for different environments
- Validate required environment variables on startup
- Prefix React env vars with REACT_APP_
- Use type-safe config classes
- Keep secrets secure
- Document required environment variables in README

---

### 28. Form Validation with React Hook Form & Zod

**What it is:** Type-safe form validation with excellent performance and UX.

**When to use:** All forms in your application.

```typescript
// Install: npm install react-hook-form zod @hookform/resolvers

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

// Define validation schema
const loginSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .email('Invalid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain uppercase letter')
    .regex(/[a-z]/, 'Must contain lowercase letter')
    .regex(/[0-9]/, 'Must contain number'),
});

type LoginFormData = z.infer<typeof loginSchema>;

const LoginForm: React.FC = () => {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    reset,
    setError,
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: '',
      password: '',
    },
  });

  const onSubmit = async (data: LoginFormData) => {
    try {
      await loginUser(data);
      // Success - redirect
    } catch (error: any) {
      // Set server-side errors
      if (error.response?.data?.field) {
        setError(error.response.data.field, {
          message: error.response.data.message,
        });
      } else {
        setError('root', {
          message: 'Login failed. Please try again.',
        });
      }
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      {/* Root error (general form error) */}
      {errors.root && (
        <div className="error">{errors.root.message}</div>
      )}

      <div>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          {...register('email')}
          aria-invalid={errors.email ? 'true' : 'false'}
        />
        {errors.email && (
          <span className="error">{errors.email.message}</span>
        )}
      </div>

      <div>
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          {...register('password')}
          aria-invalid={errors.password ? 'true' : 'false'}
        />
        {errors.password && (
          <span className="error">{errors.password.message}</span>
        )}
      </div>

      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
};

// Complex form with nested objects and arrays
const taskSchema = z.object({
  title: z.string().min(3).max(200),
  description: z.string().max(2000).optional(),
  status: z.enum(['todo', 'in_progress', 'review', 'done']),
  priority: z.enum(['low', 'medium', 'high']),
  dueDate: z.string().datetime().optional(),
  assignedTo: z.string().optional(),
  tags: z.array(z.string()).max(10).optional(),
  attachments: z.array(z.object({
    name: z.string(),
    url: z.string().url(),
  })).optional(),
});

type TaskFormData = z.infer<typeof taskSchema>;

const TaskForm: React.FC<{ onSubmit: (data: TaskFormData) => void }> = ({ onSubmit }) => {
  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
    setValue,
  } = useForm<TaskFormData>({
    resolver: zodResolver(taskSchema),
  });

  // Watch field values
  const priority = watch('priority');
  const status = watch('status');

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('title')} placeholder="Task title" />
      {errors.title && <span>{errors.title.message}</span>}

      <textarea {...register('description')} placeholder="Description" />
      
      <select {...register('status')}>
        <option value="todo">To Do</option>
        <option value="in_progress">In Progress</option>
        <option value="review">Review</option>
        <option value="done">Done</option>
      </select>

      <select {...register('priority')}>
        <option value="low">Low</option>
        <option value="medium">Medium</option>
        <option value="high">High</option>
      </select>

      {/* Conditional field based on priority */}
      {priority === 'high' && (
        <input
          {...register('dueDate')}
          type="datetime-local"
          placeholder="Due date (required for high priority)"
        />
      )}

      <button type="submit">Create Task</button>
    </form>
  );
};

// Reusable Input Component with validation
interface InputProps {
  label: string;
  name: string;
  type?: string;
  register: any;
  error?: { message?: string };
  required?: boolean;
}

const Input: React.FC<InputProps> = ({
  label,
  name,
  type = 'text',
  register,
  error,
  required = false,
}) => {
  return (
    <div className="form-group">
      <label htmlFor={name}>
        {label}
        {required && <span className="required">*</span>}
      </label>
      <input
        id={name}
        type={type}
        {...register(name)}
        className={error ? 'error' : ''}
        aria-invalid={error ? 'true' : 'false'}
      />
      {error && <span className="error-message">{error.message}</span>}
    </div>
  );
};

// Usage
const RegisterForm: React.FC = () => {
  const schema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(8),
  });

  const { register, handleSubmit, formState: { errors } } = useForm({
    resolver: zodResolver(schema),
  });

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <Input
        label="Full Name"
        name="name"
        register={register}
        error={errors.name}
        required
      />
      <Input
        label="Email"
        name="email"
        type="email"
        register={register}
        error={errors.email}
        required
      />
      <Input
        label="Password"
        name="password"
        type="password"
        register={register}
        error={errors.password}
        required
      />
      <button type="submit">Register</button>
    </form>
  );
};
```

**Key Points:**
- Use Zod for type-safe validation
- React Hook Form handles performance automatically
- Show errors inline near fields
- Disable submit button during submission
- Use `watch` to create dependent fields
- Create reusable input components
- Validate on both client and server

---

### 29. Error Boundaries

**What it is:** React components that catch JavaScript errors in child components.

**When to use:** Wrap main app sections to prevent entire app crashes.

```typescript
// src/components/ErrorBoundary.tsx
import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    // Update state so next render shows fallback UI
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log error to error reporting service
    console.error('Error caught by boundary:', error, errorInfo);
    
    // Call optional error handler
    this.props.onError?.(error, errorInfo);

    // You can also log to an error reporting service here
    // logErrorToService(error, errorInfo);

    this.setState({
      error,
      errorInfo,
    });
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  render() {
    if (this.state.hasError) {
      // Custom fallback UI
      if (this.props.fallback) {
        return this.props.fallback;
      }

      // Default fallback UI
      return (
        <div className="error-boundary">
          <h2>Something went wrong</h2>
          <details style={{ whiteSpace: 'pre-wrap' }}>
            <summary>Error Details</summary>
            {this.state.error?.toString()}
            <br />
            {this.state.errorInfo?.componentStack}
          </details>
          <button onClick={this.handleReset}>Try Again</button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;

// Usage in App
import ErrorBoundary from './components/ErrorBoundary';

function App() {
  const handleError = (error: Error, errorInfo: ErrorInfo) => {
    // Send to error tracking service (e.g., Sentry)
    console.error('App error:', error, errorInfo);
  };

  return (
    <ErrorBoundary
      onError={handleError}
      fallback={
        <div className="error-page">
          <h1>Oops! Something went wrong</h1>
          <p>We're working on fixing this issue.</p>
          <button onClick={() => window.location.reload()}>
            Reload Page
          </button>
        </div>
      }
    >
      <Router>
        <Routes>
          {/* Your routes */}
        </Routes>
      </Router>
    </ErrorBoundary>
  );
}

// Multiple error boundaries for different sections
function App() {
  return (
    <div>
      <ErrorBoundary fallback={<div>Header error</div>}>
        <Header />
      </ErrorBoundary>

      <ErrorBoundary fallback={<div>Main content error</div>}>
        <MainContent />
      </ErrorBoundary>

      <ErrorBoundary fallback={<div>Sidebar error</div>}>
        <Sidebar />
      </ErrorBoundary>
    </div>
  );
}

// Hook-based alternative (for function components)
import { useErrorHandler } from 'react-error-boundary';

const MyComponent: React.FC = () => {
  const handleError = useErrorHandler();

  const fetchData = async () => {
    try {
      const data = await api.getData();
    } catch (error) {
      // This will be caught by error boundary
      handleError(error);
    }
  };

  return <div>{/* component */}</div>;
};
```

**Key Points:**
- Error boundaries catch rendering errors
- Don't catch errors in event handlers (use try-catch)
- Wrap different app sections separately
- Provide user-friendly error messages
- Log errors to monitoring service
- Offer recovery options (retry, reload)

---

### 30. Production Build & Deployment

**What it is:** Preparing your app for production deployment.

**When to use:** Before deploying to production servers.

```bash
# Frontend Build
npm run build

# Creates optimized production build in /build folder
# - Minified JavaScript
# - CSS optimization
# - Image optimization
# - Source maps (optional)

# Backend Build (TypeScript)
npm run build
# Compiles TypeScript to JavaScript in /dist folder

# Production Environment Variables
# .env.production
NODE_ENV=production
MONGODB_URI=mongodb+srv://user:password@cluster.mongodb.net/production
JWT_ACCESS_SECRET=long-random-secure-string
JWT_REFRESH_SECRET=another-long-random-secure-string
FRONTEND_URL=https://yourdomain.com
```

**Backend Production Setup:**
```typescript
// src/server.ts - Production configuration
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

// Compression
app.use(compression());

// Sanitize data against NoSQL injection
app.use(mongoSanitize());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Stricter rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/build/index.html'));
  });
}

// Global error handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;

  res.status(err.statusCode || 500).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});

const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});
```

**Docker Configuration:**
```dockerfile
# Dockerfile for Backend
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose port
EXPOSE 5000

# Start application
CMD ["node", "dist/server.js"]

# .dockerignore
node_modules
npm-debug.log
.env
.git
.gitignore
README.md
```

**Docker Compose:**
```yaml
# docker-compose.yml
version: '3.8'

services:
  mongodb:
    image: mongo:6
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: password
    volumes:
      - mongodb_data:/data/db
    ports:
      - "27017:27017"

  backend:
    build: ./backend
    restart: always
    ports:
      - "5000:5000"
    environment:
      NODE_ENV: production
      MONGODB_URI: mongodb://admin:password@mongodb:27017/taskmanager?authSource=admin
      JWT_ACCESS_SECRET: ${JWT_ACCESS_SECRET}
      JWT_REFRESH_SECRET: ${JWT_REFRESH_SECRET}
    depends_on:
      - mongodb

  frontend:
    build: ./frontend
    restart: always
    ports:
      - "80:80"
    depends_on:
      - backend

volumes:
  mongodb_data:
```

**Deployment Checklist:**
```typescript
const productionChecklist = {
  backend: {
    security: [
      '✓ Helmet.js configured',
      '✓ CORS properly configured',
      '✓ Rate limiting enabled',
      '✓ Input validation on all routes',
      '✓ SQL/NoSQL injection protection',
      '✓ XSS protection',
      '✓ HTTPS enabled',
      '✓ Security headers set',
    ],
    performance: [
      '✓ Compression enabled',
      '✓ Database indexes created',
      '✓ Connection pooling configured',
      '✓ Caching implemented',
    ],
    monitoring: [
      '✓ Error logging configured',
      '✓ Performance monitoring',
      '✓ Health check endpoint',
    ],
    environment: [
      '✓ All secrets in environment variables',
      '✓ No hardcoded credentials',
      '✓ Production MongoDB configured',
      '✓ Backup strategy in place',
    ],
  },
  frontend: {
    build: [
      '✓ Production build tested',
      '✓ Source maps disabled or separate',
      '✓ Bundle size optimized',
      '✓ Images optimized',
    ],
    security: [
      '✓ CSP headers configured',
      '✓ XSS protection implemented',
      '✓ Sensitive data not exposed',
      '✓ HTTPS enforced',
    ],
    performance: [
      '✓ Code splitting implemented',
      '✓ Lazy loading for routes',
      '✓ Assets minified',
      '✓ Caching strategy defined',
    ],
  },
  general: [
    '✓ Environment variables documented',
    '✓ README updated',
    '✓ API documentation available',
    '✓ Database migrations tested',
    '✓ Rollback plan prepared',
    '✓ Monitoring alerts configured',
  ],
};
```

**Performance Optimization:**
```typescript
// Code splitting in React
import React, { lazy, Suspense } from 'react';

// Lazy load components
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Tasks = lazy(() => import('./pages/Tasks'));
const Admin = lazy(() => import('./pages/Admin'));

function App() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/tasks" element={<Tasks />} />
        <Route path="/admin" element={<Admin />} />
      </Routes>
    </Suspense>
  );
}

// Memoization for expensive computations
import { useMemo, useCallback } from 'react';

const TaskList: React.FC<{ tasks: Task[] }> = ({ tasks }) => {
  // Memoize filtered data
  const filteredTasks = useMemo(() => {
    return tasks.filter(task => task.status !== 'done');
  }, [tasks]);

  // Memoize callbacks
  const handleDelete = useCallback((id: string) => {
    deleteTask(id);
  }, []);

  return (
    <div>
      {filteredTasks.map(task => (
        <TaskCard key={task.id} task={task} onDelete={handleDelete} />
      ))}
    </div>
  );
};

// React.memo for component memoization
const TaskCard = React.memo<{ task: Task; onDelete: (id: string) => void }>(
  ({ task, onDelete }) => {
    return (
      <div>
        <h3>{task.title}</h3>
        <button onClick={() => onDelete(task.id)}>Delete</button>
      </div>
    );
  }
);
```

**Key Points:**
- Enable compression and security headers
- Use rate limiting in production
- Don't expose stack traces to users
- Implement proper error logging
- Use environment variables for configuration
- Enable HTTPS
- Optimize bundle size
- Implement monitoring and alerts
- Test production build before deployment
- Have a rollback plan

---

## Summary & Best Practices

### Security Best Practices
1. **Never trust user input** - Validate on both client and server
2. **Use httpOnly cookies** for tokens when possible
3. **Implement rate limiting** to prevent abuse
4. **Keep dependencies updated** to patch vulnerabilities
5. **Use HTTPS** in production always
6. **Hash passwords** with bcrypt (never plain text)
7. **Implement CSRF protection** with SameSite cookies
8. **Sanitize HTML** before displaying user content
9. **Use environment variables** for secrets
10. **Log security events** for audit trails

### Code Organization Best Practices
1. **Separate concerns** - Use MVC pattern
2. **Create reusable components** and hooks
3. **Type everything** with TypeScript
4. **Use consistent naming** conventions
5. **Keep functions small** and focused
6. **Write self-documenting code**
7. **Handle errors gracefully**
8. **Use middleware** for cross-cutting concerns
9. **Organize by feature** not by type
10. **Write tests** for critical paths

### Performance Best Practices
1. **Use React Query** for server state
2. **Implement pagination** for large lists
3. **Add database indexes** for frequent queries
4. **Use memoization** wisely (useMemo, useCallback)
5. **Lazy load routes** and heavy components
6. **Optimize images** and assets
7. **Enable compression** on backend
8. **Cache API responses** appropriately
9. **Use connection pooling** for database
10. **Monitor performance** metrics

### Development Workflow
1. **Use Git branches** for features
2. **Write meaningful commits**
3. **Code review** before merging
4. **Test locally** before pushing
5. **Use linting** and formatting tools
6. **Document complex logic**
7. **Keep dependencies minimal**
8. **Update packages** regularly
9. **Follow coding standards**
10. **Learn from mistakes**

---

## Useful Commands Reference

```bash
# React/Frontend
npx create-react-app my-app --template typescript
npm install @reduxjs/toolkit react-redux
npm install @tanstack/react-query
npm install react-router-dom
npm install axios
npm install react-hook-form zod @hookform/resolvers
npm start  # Development server
npm run build  # Production build

# Node.js/Backend
npm init -y
npm install express mongoose dotenv
npm install bcryptjs jsonwebtoken
npm install cors helmet express-rate-limit morgan
npm install zod
npm install -D typescript @types/node @types/express
npm install -D nodemon ts-node
npx tsc --init  # Create tsconfig.json
npm run dev  # Start dev server

# MongoDB
mongod  # Start MongoDB locally
mongosh  # MongoDB shell
use taskmanager  # Switch database
db.users.find()  # Query collection

# Git
git init
git add .
git commit -m "Initial commit"
git branch feature/add-auth
git checkout feature/add-auth
git merge main

# Docker
docker build -t my-app .
docker run -p 5000:5000 my-app
docker-compose up -d
docker-compose down
```

---

This reference guide covers all the essential topics from the 4-week learning plan. Keep this handy while working through the project and refer back to specific sections as needed. Good luck with your learning journey! 🚀
