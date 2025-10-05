4‑Week MERN + TypeScript Intensive: Study Plan + Project (SecureNotes)

Goal: bring a colleague from shaky MERN knowledge to solid full‑stack competency (TypeScript + Node/Express + MongoDB + React + Redux Toolkit + React Query), with strong practical knowledge of middleware, authentication & authorization, encryption, and common web app security patterns.

This document contains:
	•	A 4‑week plan with weekly learning goals and daily exercises.
	•	A detailed small project (SecureNotes) with full requirements, API spec, DB models, folder structure and a step‑by‑step execution plan.
	•	Code examples (TypeScript + JS) for critical pieces: server, middleware, auth, encryption, frontend store, axios + interceptors, protected routing.
	•	Security checklist and evaluation rubric.

⸻

What to expect / prerequisites
	•	Prior knowledge assumed: basic JavaScript, git, basic HTML/CSS, familiarity with Node.js/npm. If not, add 3–5 days of prework.
	•	Suggested cadence: practice/coding every weekday. Use weekends for deeper practice, polish and catch‑up. The plan is modular — skip or move items based on the colleague’s pace.

⸻

Week 1 — Foundations: TypeScript + Node basics + Project scaffolding

Learning goals: TypeScript basics & patterns useful in full‑stack apps, setup a typed Node/Express backend, create DB models with types.

Day‑by‑day (high level)
	•	Day 1 — TypeScript essentials: types (primitive, union, tuple), interfaces vs types, enums, type inference, tsconfig essentials.
	•	Exercises: convert small JS snippets to TS; create a typed User shape.
	•	Day 2 — TS advanced: generics, utility types (Partial, Pick, Omit, Record), unknown vs any, mapped types.
	•	Exercise: write a typed Repository<T> interface for CRUD operations.
	•	Day 3 — Node + Express in TS: set up project, ts-node-dev or esbuild for dev, basic Express server, dotenv config.
	•	Day 4 — MongoDB + Mongoose + Types: design Mongoose schemas with TypeScript interfaces; basic connection & error handling.
	•	Day 5 — Project scaffolding & README: create monorepo or two repos (backend/frontend), define env variables, create skeleton routes and start scripts.

Quick examples (setup snippets)

tsconfig.json (minimal)

{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "dist",
    "sourceMap": true
  },
  "include": ["src"]
}

Install (backend)

npm init -y
npm i express mongoose dotenv bcryptjs jsonwebtoken cookie-parser helmet cors
npm i -D typescript ts-node-dev @types/express @types/node @types/cookie-parser

Basic Express server (src/server.ts)

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_ORIGIN, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.get('/_health', (_req, res) => res.json({ ok: true }));

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Server running on ${port}`));



⸻

Week 2 — Server internals, middleware, auth basics & encryption fundamentals

Learning goals: write robust middleware, implement registration/login with secure password storage, JWT + refresh tokens concept, basic encryption for sensitive fields.

Topics & exercises
	•	Middleware patterns: request validation, central error handler, logging middleware (winston or simple console), async error wrapper.
	•	Auth flow: register (hash with bcrypt), login (verify + issue access token + refresh token), protect routes with middleware, role checks.
	•	Refresh token best practices: rotate refresh tokens, store refresh tokens in DB (or short lived with fingerprint) and set refresh cookie as HttpOnly; Secure; SameSite=Strict.
	•	Encryption: symmetric encryption for storing sensitive user data (not passwords!) using Node crypto (AES‑GCM recommended). Passwords must be hashed, not encrypted.

Key code snippets

User model (Mongoose, simplified)

import { Schema, model, Document } from 'mongoose';

export interface IUser extends Document {
  email: string;
  passwordHash: string;
  role: 'user' | 'admin';
}

const UserSchema = new Schema<IUser>({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: 'user' }
}, { timestamps: true });

export const UserModel = model<IUser>('User', UserSchema);

Register & Login (essential parts)

// utils/auth.ts
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export async function hashPassword(pw: string) {
  return bcrypt.hash(pw, 12);
}
export async function comparePassword(pw: string, hash: string) {
  return bcrypt.compare(pw, hash);
}
export function signAccessToken(payload: object) {
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: '15m' });
}
export function signRefreshToken(payload: object) {
  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET!, { expiresIn: '7d' });
}

Auth middleware (protect routes)

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ message: 'No token' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!);
    // attach user to req (cast as any) - in prod, use typed request
    (req as any).user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

Symmetric encrypt/decrypt util (AES‑256‑GCM)

import crypto from 'crypto';

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;

export function encrypt(text: string, keyBase64: string) {
  const key = Buffer.from(keyBase64, 'base64');
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

export function decrypt(payloadB64: string, keyBase64: string) {
  const data = Buffer.from(payloadB64, 'base64');
  const iv = data.slice(0, IV_LEN);
  const tag = data.slice(IV_LEN, IV_LEN + 16);
  const encrypted = data.slice(IV_LEN + 16);
  const key = Buffer.from(keyBase64, 'base64');
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

Note: store encryption keys in secure secrets (env manager, Vault). Never commit keys.

⸻

Week 3 — Frontend: React + TypeScript + Redux Toolkit + React Query + secure navigation

Learning goals: build typed React apps with state management and server data fetching, implement secure auth flows client side, protect navigation and sensitive routes, use react-query for server state.

Topics & exercises
	•	Scaffold: create Vite + React + TypeScript app.
	•	Forms & validation: react-hook-form + zod for typed validation and runtime checks.
	•	State management: Redux Toolkit for global UI/auth state; keep minimal state (auth metadata). Use RTK query only if needed — otherwise prefer React Query for server data.
	•	React Query: use useQuery/useMutation, caching strategy, optimistic updates for CRUD.
	•	Auth patterns: store access token in memory (React context / Redux), refresh token as HttpOnly cookie; implement Axios instance with interceptor that attempts refresh on 401.
	•	Navigation security: ProtectedRoute component, role guard, route-level lazy loading and avoiding leaking protected UI.

Frontend code snippets

Axios instance with interceptor (errors -> refresh)

// src/api/axios.ts
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE,
  withCredentials: true // important for HttpOnly refresh cookie
});

let isRefreshing = false;
let refreshSubscribers: ((token: string) => void)[] = [];

function onRefreshed(token: string) {
  refreshSubscribers.forEach(cb => cb(token));
  refreshSubscribers = [];
}

api.interceptors.response.use(
  r => r,
  async err => {
    const original = err.config;
    if (err.response?.status === 401 && !original._retry) {
      original._retry = true;
      if (!isRefreshing) {
        isRefreshing = true;
        try {
          const { data } = await api.post('/auth/refresh');
          isRefreshing = false;
          onRefreshed(data.accessToken);
        } catch (e) {
          isRefreshing = false;
          // redirect to login
          window.location.href = '/login';
          return Promise.reject(e);
        }
      }
      return new Promise((resolve) => {
        refreshSubscribers.push((token: string) => {
          original.headers.Authorization = `Bearer ${token}`;
          resolve(axios(original));
        });
      });
    }
    return Promise.reject(err);
  }
);

export default api;

Protected route (React Router v6)

import { Navigate, Outlet } from 'react-router-dom';
import { useAppSelector } from '../store/hooks';

export function RequireAuth({ allowedRoles }: { allowedRoles?: string[] }) {
  const auth = useAppSelector(s => s.auth);
  if (!auth.isAuthenticated) return <Navigate to="/login" replace />;
  if (allowedRoles && !allowedRoles.includes(auth.user?.role)) return <Navigate to="/unauthorized" replace />;
  return <Outlet />;
}

React Query example (fetch notes)

import { useQuery } from '@tanstack/react-query';
import api from './axios';

export function useNotes() {
  return useQuery(['notes'], async () => {
    const { data } = await api.get('/notes');
    return data;
  }, { staleTime: 1000 * 60 });
}



⸻

Week 4 — Hardening, testing, deployment, final polish

Learning goals: security hardening, logging, tests, CI, containerization, final project delivery.

Topics & checklist
	•	Server hardening: Helmet CSP config, remove X-Powered-By, rate limiting (express-rate-limit), enforce HTTPS (redirect), CORS whitelist.
	•	Input validation & sanitization: use zod or joi on all endpoints, sanitize strings to prevent XSS on output.
	•	Secrets & configs: load from env, do not commit .env, use .env.example.
	•	Logging & monitoring: structured logs, request IDs, error telemetry (Sentry), audit logs for critical actions (login, role change, share note).
	•	Testing: unit tests for utilities (auth, encrypt), integration tests for APIs (supertest), UI tests (React Testing Library), e2e (Cypress).
	•	Deployment: Dockerize backend & frontend, use docker-compose for local stack, set up basic CI (GitHub Actions) for build + test + lint.

⸻

Project: SecureNotes — full details

Short description: SecureNotes is a small MERN app where registered users can create encrypted personal notes, optionally share them with other users (authorization), and admins can manage users. The project requires strong focus on authentication, token management, encryption of note content at rest, and secure client/server interactions.

Features (MVP)
	1.	User registration + login (email + password) with hashed password.
	2.	JWT access tokens + refresh tokens (HttpOnly cookie). Access token used for API calls.
	3.	Create, Read, Update, Delete notes. Note content stored encrypted in DB.
	4.	Share note with another user (simple sharing model: grant read / edit rights).
	5.	Role based pages: user and admin (admin can list and deactivate users).
	6.	Audit log of critical events: login, failed login, note shared, note deleted.

Tech stack
	•	Backend: Node.js, Express, TypeScript, Mongoose, bcrypt, jsonwebtoken, helmet, cors, express-rate-limit
	•	Frontend: React + TypeScript (Vite), Redux Toolkit, React Query, React Router v6, Axios, react-hook-form + zod
	•	DB: MongoDB (Atlas or local)
	•	Dev tools: Docker, Jest/RTL, Supertest, ESLint, Prettier

Folder structure (suggested)

secure-notes/
  backend/
    src/
      controllers/
      services/
      middlewares/
      models/
      utils/
      routes/
      server.ts
    package.json
    tsconfig.json
  frontend/
    src/
      components/
      pages/
      hooks/
      api/
      store/
      App.tsx
    package.json
    tsconfig.json
  docker-compose.yml
  README.md

DB Models (simplified)

User

interface User {
  _id: ObjectId;
  email: string;
  passwordHash: string;
  role: 'user' | 'admin';
  disabled?: boolean;
}

Note

interface Note {
  _id: ObjectId;
  ownerId: ObjectId;
  title: string; // optional to store plaintext or encrypted
  contentEncrypted: string; // encrypted blob (base64)
  sharedWith: Array<{ userId: ObjectId; permissions: 'read' | 'edit' }>;
  createdAt: Date;
}

RefreshToken (optional)

interface RefreshToken {
  token: string;
  userId: ObjectId;
  expiresAt: Date;
  revoked?: boolean;
  fingerprint?: string; // optional client fingerprint
}

API spec (example endpoints)
	•	POST /api/auth/register — body { email, password } -> 201 created
	•	POST /api/auth/login — body { email, password } -> returns { accessToken } and sets refresh cookie
	•	POST /api/auth/refresh — reads refresh cookie -> sets new accessToken (and rotate refresh)
	•	POST /api/auth/logout — invalidates refresh token (clear cookie)
	•	GET /api/notes — auth required -> returns user notes and shared notes
	•	POST /api/notes — auth required -> create note (encrypt content server side)
	•	PUT /api/notes/:id — update note (owner or edit permission)
	•	POST /api/notes/:id/share — share note with user (owner only)

Include request/response examples in real implementation (use Postman for testing).

⸻

Step‑by‑step execution plan (milestones + tasks)

Milestone 0: repo & environment
	1.	Create secure-notes repo (or two repos). Add .gitignore, README, .env.example.
	2.	Create backend scaffold (npm, TypeScript, Express). Create start/dev scripts.
	3.	Create frontend scaffold (Vite). Add eslint + prettier configs.

Milestone 1: Basic auth & user model
	1.	Implement User model and DB connection.
	2.	Implement POST /auth/register that hashes password and saves user.
	3.	Implement POST /auth/login that verifies password and issues access token and sets refresh cookie.
	4.	Implement requireAuth middleware and a protected test endpoint GET /me.

Milestone 2: Notes CRUD + encryption
	1.	Implement Note model; create encrypt() / decrypt() util.
	2.	Implement POST /notes that encrypts content server‑side before saving.
	3.	Implement GET /notes to decrypt notes for authorized user.
	4.	Implement PUT /notes/:id and DELETE /notes/:id with permission checks.

Milestone 3: Sharing & roles
	1.	Implement POST /notes/:id/share — send invite or set sharedWith.
	2.	Implement admin routes to list/deactivate users.
	3.	Add audit logging for share/delete/login events.

Milestone 4: Refresh tokens & client flows
	1.	Implement refresh token storage (DB) and endpoint to rotate/issue new tokens.
	2.	Frontend: implement login/register pages. Store accessToken in memory and rely on refresh cookie.
	3.	Implement Axios interceptor to refresh on 401.

Milestone 5: Hardening, tests & deployment
	1.	Add helmet, rate limiter, input validation, CORS whitelist.
	2.	Add unit tests (Jest) and integration tests (supertest).
	3.	Dockerize and create docker-compose for local dev, add README with run steps.
	4.	Add CI workflow to run lint/test/build on PRs.

⸻



#####################################################################

# 4-Week MERN Stack Mastery Plan

## Overview
This plan transforms a developer into a proficient full-stack MERN engineer with strong TypeScript foundations, security awareness, and best practices.

---

## Week 1: TypeScript Foundations & Backend Basics

### Learning Objectives
- Master TypeScript fundamentals and advanced types
- Understand Node.js/Express architecture
- Learn middleware concepts and implementation
- Grasp basic security principles

### Daily Breakdown

#### Day 1-2: TypeScript Essentials
**Topics:**
- Type annotations, interfaces, and type aliases
- Generics and utility types (Partial, Pick, Omit, Record)
- Enums and literal types
- Type guards and discriminated unions
- Configuring tsconfig.json for Node.js projects

**Resources:**
- TypeScript Handbook (official docs)
- Practice on TypeScript playground

**Exercise:**
Create a TypeScript utility library with:
- Type-safe API response handlers
- Custom error classes with proper typing
- Database model interfaces

---

#### Day 3-4: Node.js & Express Foundation
**Topics:**
- Express routing and route organization
- Request/Response lifecycle
- Error handling patterns
- Environment configuration with dotenv
- File structure best practices (MVC pattern)

**Key Concepts:**
```
project-structure/
├── src/
│   ├── config/       # Configuration files
│   ├── controllers/  # Request handlers
│   ├── models/       # Database models
│   ├── routes/       # Route definitions
│   ├── middleware/   # Custom middleware
│   ├── utils/        # Helper functions
│   ├── types/        # TypeScript types
│   └── server.ts     # Entry point
```

---

#### Day 5-7: Middleware & Security Basics
**Topics:**
- Built-in middleware (express.json, express.urlencoded)
- Third-party middleware (cors, helmet, morgan)
- Custom middleware creation
- Error handling middleware
- Request validation with Zod or Joi
- Rate limiting and request throttling
- Input sanitization

**Security Concepts:**
- CORS configuration
- Helmet.js for HTTP headers
- SQL injection prevention
- XSS protection
- CSRF tokens

**Mini Project:**
Build a "Secure API Starter" with:
- Error handling middleware
- Request logging
- Input validation middleware
- Rate limiting
- Security headers

---

## Week 2: Authentication, Authorization & Database

### Learning Objectives
- Implement JWT-based authentication
- Understand authorization patterns (RBAC)
- Master password encryption
- Learn MongoDB operations with Mongoose
- Implement refresh token rotation

### Daily Breakdown

#### Day 1-2: Authentication Deep Dive
**Topics:**
- Password hashing with bcrypt (salt rounds, comparison)
- JWT structure (header, payload, signature)
- Access tokens vs Refresh tokens
- Token storage strategies (httpOnly cookies vs localStorage)
- Token expiration and renewal

**Implementation:**
- User registration with password hashing
- Login with JWT generation
- Protected routes with JWT verification middleware
- Refresh token endpoint
- Logout functionality (token blacklisting)

---

#### Day 3-4: Authorization & Role-Based Access
**Topics:**
- Role-Based Access Control (RBAC)
- Permission-based authorization
- Middleware for role checking
- Resource ownership verification

**Pattern:**
```typescript
// Role hierarchy: user < moderator < admin
// Implement middleware:
- requireAuth (is logged in?)
- requireRole(['admin', 'moderator'])
- requireOwnership (user owns resource?)
```

---

#### Day 5-7: MongoDB & Data Security
**Topics:**
- Mongoose schemas and models
- Schema validation
- Virtual properties and methods
- Pre/post hooks
- Population and references
- Indexing for performance
- Data encryption at rest
- Sensitive data handling (PII)

**Best Practices:**
- Never store plain text passwords
- Encrypt sensitive fields (SSN, credit cards) with crypto
- Implement data access logs
- Use projections to exclude sensitive fields

---

## Week 3: Frontend with React & State Management

### Learning Objectives
- Master React with TypeScript
- Implement Redux Toolkit properly
- Learn React Query for server state
- Handle client-side authentication
- Implement protected routes

### Daily Breakdown

#### Day 1-2: React + TypeScript
**Topics:**
- Functional components with TypeScript
- Props and state typing
- Event handlers typing
- useRef, useCallback, useMemo with proper types
- Custom hooks with TypeScript
- Context API with types

**Components to Build:**
- Typed form components
- Reusable UI components (Button, Input, Card)
- Error boundary component
- Loading states handler

---

#### Day 3-4: Redux Toolkit
**Topics:**
- Slices and reducers
- Async thunks for API calls
- Redux DevTools
- TypeScript with Redux (RootState, AppDispatch)
- Selector patterns with reselect
- Redux persist for local storage

**Store Structure:**
```typescript
store/
├── slices/
│   ├── authSlice.ts
│   ├── userSlice.ts
│   └── uiSlice.ts
├── api/
│   └── apiSlice.ts  // RTK Query
└── store.ts
```

---

#### Day 5-7: React Query & API Integration
**Topics:**
- React Query setup and configuration
- Queries vs Mutations
- Cache management
- Optimistic updates
- Error handling
- Infinite queries and pagination
- Query invalidation strategies

**When to use Redux vs React Query:**
- Redux: Global UI state, client-only state
- React Query: Server state, API data

**API Integration:**
- Axios interceptors for token refresh
- Error handling middleware
- Request/response transformations
- Retry logic

---

## Week 4: Frontend Security & Production Deployment

### Learning Objectives
- Implement navigation security
- Handle sensitive data on frontend
- Learn secure storage practices
- Deployment and environment management
- Performance optimization

### Daily Breakdown

#### Day 1-2: Frontend Security
**Topics:**
- Protected routes implementation
- Role-based route access
- Secure token storage (httpOnly cookies preferred)
- XSS prevention in React
- Content Security Policy
- Preventing token leakage in console/errors
- Secure form handling

**Route Protection Pattern:**
```typescript
// ProtectedRoute component
// PublicOnlyRoute (login/register when logged out)
// RoleBasedRoute (admin routes)
```

---

#### Day 3-4: Navigation & Authorization
**Topics:**
- React Router v6 advanced patterns
- Nested routes and layouts
- Navigation guards
- Conditional rendering based on permissions
- Preventing unauthorized access to UI elements

**Security Checklist:**
- ✓ Never store sensitive data in localStorage
- ✓ Clear tokens on logout
- ✓ Validate on both client AND server
- ✓ Don't expose role/permissions in URL
- ✓ Implement proper error messages (no info leakage)

---

#### Day 5-7: Deployment & Best Practices
**Topics:**
- Environment variables management
- Building for production
- Docker containerization basics
- CI/CD concepts
- HTTPS and SSL certificates
- Security headers in production
- Logging and monitoring

**Production Checklist:**
- [ ] Environment variables secured
- [ ] HTTPS enabled
- [ ] Security headers configured
- [ ] Rate limiting active
- [ ] Error tracking setup
- [ ] Database backups configured
- [ ] CORS properly configured

---

## Final Project: Secure Task Management System

### Project Overview
Build a full-stack task management application with teams, role-based access, and secure authentication.

### Features Required

#### Authentication System
- User registration with email verification
- Login with JWT (access + refresh tokens)
- Password reset functionality
- Account lockout after failed attempts
- Session management

#### Authorization System
- Three roles: Admin, Manager, User
- Admin: Full system access
- Manager: Team management, task assignment
- User: Own tasks only
- Resource ownership checks

#### Core Functionality
- Create/edit/delete tasks
- Assign tasks to team members
- Task status workflow (Todo → In Progress → Review → Done)
- Team creation and management
- File attachments with security validation
- Activity logs (audit trail)
- Real-time notifications (optional)

---

### Technical Requirements

#### Backend
**Stack:**
- Node.js + Express + TypeScript
- MongoDB + Mongoose
- JWT for authentication
- Bcrypt for password hashing

**Must Implement:**
1. Structured error handling
2. Request validation (Zod)
3. Rate limiting (express-rate-limit)
4. Security middleware (helmet, cors)
5. File upload validation (size, type)
6. Pagination and filtering
7. Proper HTTP status codes
8. API documentation (comments or Swagger)

**API Endpoints:**
```
Auth:
POST   /api/auth/register
POST   /api/auth/login
POST   /api/auth/refresh
POST   /api/auth/logout
POST   /api/auth/forgot-password
POST   /api/auth/reset-password

Users:
GET    /api/users/profile
PUT    /api/users/profile
GET    /api/users (admin only)

Teams:
GET    /api/teams
POST   /api/teams (manager+)
PUT    /api/teams/:id (manager+)
DELETE /api/teams/:id (admin only)
POST   /api/teams/:id/members (manager+)

Tasks:
GET    /api/tasks
GET    /api/tasks/:id
POST   /api/tasks
PUT    /api/tasks/:id
DELETE /api/tasks/:id
PATCH  /api/tasks/:id/status
POST   /api/tasks/:id/assign
```

---

#### Frontend
**Stack:**
- React + TypeScript
- Redux Toolkit for auth state
- React Query for server state
- React Router v6
- Tailwind CSS (or Material-UI)

**Must Implement:**
1. Protected routes by authentication
2. Role-based route protection
3. Secure token management
4. Form validation
5. Error boundaries
6. Loading states
7. Optimistic updates for better UX
8. Responsive design

**Pages Required:**
- Login / Register
- Dashboard (role-specific)
- Task List (filterable, sortable)
- Task Details
- Task Create/Edit
- Team Management (manager+)
- User Profile
- Admin Panel (admin only)

---

### Step-by-Step Execution Plan

#### Phase 1: Planning & Setup (Day 1)

**1. Project Initialization**
```bash
# Backend
mkdir task-manager-api && cd task-manager-api
npm init -y
npm install express mongoose dotenv bcryptjs jsonwebtoken
npm install cors helmet express-rate-limit morgan zod
npm install -D typescript @types/node @types/express
npm install -D @types/bcryptjs @types/jsonwebtoken
npm install -D nodemon ts-node

# Frontend
npx create-react-app task-manager-client --template typescript
cd task-manager-client
npm install @reduxjs/toolkit react-redux react-router-dom
npm install @tanstack/react-query axios
npm install react-hook-form zod @hookform/resolvers
```

**2. Setup TypeScript Config**
- Configure tsconfig.json for backend
- Ensure strict mode enabled
- Set up path aliases

**3. Environment Setup**
```
# .env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/taskmanager
JWT_ACCESS_SECRET=your-access-secret-key
JWT_REFRESH_SECRET=your-refresh-secret-key
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
```

---

#### Phase 2: Backend - Auth & Security (Day 2-4)

**Day 2: Database Models**
1. Create User model
   - Fields: email, password (hashed), name, role, isActive, lastLogin
   - Pre-save hook for password hashing
   - Method to compare passwords
   - Exclude password from JSON responses

2. Create RefreshToken model
   - Fields: token, userId, expiresAt, isRevoked
   - TTL index for auto-deletion

**Day 3: Authentication Logic**
1. Implement registration controller
   - Validate input (email format, password strength)
   - Check duplicate email
   - Hash password
   - Create user
   - Generate tokens
   - Return user data (no password)

2. Implement login controller
   - Validate credentials
   - Compare password
   - Generate JWT tokens
   - Store refresh token in DB
   - Set httpOnly cookie (recommended) or return in response
   - Update lastLogin

3. Implement refresh token endpoint
   - Verify refresh token
   - Check if revoked
   - Generate new access token
   - Rotate refresh token (optional but recommended)

4. Implement logout
   - Revoke refresh token
   - Clear cookies

**Day 4: Middleware & Security**
1. Create authMiddleware
   - Extract token from header/cookie
   - Verify token
   - Attach user to request

2. Create roleMiddleware
   - Check user role against allowed roles
   - Return 403 if unauthorized

3. Create validation middleware
   - Use Zod for schema validation
   - Return structured errors

4. Add security middleware
   - helmet for security headers
   - CORS configuration
   - Rate limiting on auth routes
   - Request logging

---

#### Phase 3: Backend - Core Features (Day 5-7)

**Day 5: Team Management**
1. Create Team model
   - Fields: name, description, members[], createdBy, createdAt
   - Virtual for member count

2. Implement team controllers
   - Create team (manager+)
   - Get teams (user sees only their teams)
   - Update team (manager of team)
   - Add/remove members (manager of team)
   - Delete team (admin or creator)

3. Implement ownership middleware
   - Check if user is team manager
   - Check if user is team member

**Day 6: Task Management**
1. Create Task model
   - Fields: title, description, status, priority, assignedTo, teamId, createdBy, dueDate, attachments[]
   - Enum for status: TODO, IN_PROGRESS, REVIEW, DONE
   - Populate references

2. Implement task controllers
   - Create task (authenticated users)
   - Get tasks (filtered by role)
     - Users: only assigned tasks
     - Managers: team tasks
     - Admins: all tasks
   - Update task (owner or assignee)
   - Delete task (owner or admin)
   - Change status (assignee or manager)
   - Assign task (manager+)

**Day 7: Additional Features**
1. Implement filtering & pagination
   - Query params: page, limit, status, priority, assignedTo
   - Sort options

2. File upload handling
   - Validate file type and size
   - Store securely (use multer)
   - Generate secure URLs

3. Activity logging
   - Log important actions
   - Store in separate collection

4. Testing & Debugging
   - Test all endpoints with Postman
   - Verify authorization works
   - Test error scenarios

---

#### Phase 4: Frontend - Setup & Auth (Day 8-10)

**Day 8: Project Structure & Routing**
1. Setup folder structure
```
src/
├── components/
│   ├── common/
│   ├── auth/
│   ├── tasks/
│   └── teams/
├── pages/
├── store/
│   └── slices/
├── services/
├── hooks/
├── types/
├── utils/
└── config/
```

2. Configure React Router
   - Public routes (login, register)
   - Protected routes (dashboard, tasks)
   - Role-based routes (admin panel)

3. Create route guards
   - ProtectedRoute component
   - PublicOnlyRoute component
   - RoleBasedRoute component

**Day 9: Redux Setup**
1. Configure Redux store
   - authSlice (user, tokens, isAuthenticated)
   - uiSlice (loading, errors, notifications)

2. Create auth actions
   - login
   - logout
   - refreshToken
   - Update user profile

3. Implement Redux persist
   - Persist auth state
   - Exclude sensitive data

**Day 10: API Integration**
1. Create axios instance
   - Base URL configuration
   - Request interceptor (add token)
   - Response interceptor (handle errors, refresh token)

2. Create auth service
   - login()
   - register()
   - logout()
   - refreshToken()
   - getCurrentUser()

3. Build auth pages
   - Login form with validation
   - Register form
   - Password strength indicator
   - Error handling display
   - Loading states

---

#### Phase 5: Frontend - Core Features (Day 11-13)

**Day 11: React Query Setup**
1. Configure React Query
   - QueryClient setup
   - Default options (retry, staleTime)

2. Create query hooks
   - useTasksQuery
   - useTeamsQuery
   - useUsersQuery (admin)

3. Create mutation hooks
   - useCreateTask
   - useUpdateTask
   - useDeleteTask
   - useAssignTask

**Day 12: Task Management UI**
1. Task list component
   - Display tasks in cards/table
   - Filtering by status, priority
   - Sorting options
   - Pagination controls
   - Search functionality

2. Task detail component
   - Full task information
   - Edit capability (if authorized)
   - Status change buttons
   - Assignment interface
   - File attachments

3. Task form component
   - Create/edit form
   - Form validation with react-hook-form + zod
   - Date picker for due date
   - Team/user selection
   - File upload

**Day 13: Team Management UI**
1. Team list component
   - Display user's teams
   - Create team button (manager+)

2. Team detail component
   - Member list
   - Add/remove members (if manager)
   - Team tasks overview

3. Role-based UI rendering
   - Show/hide features by role
   - Disable actions user can't perform
   - Clear messaging about permissions

---

#### Phase 6: Security & Polish (Day 14)

**Morning: Security Audit**
1. Frontend security
   - Review token storage (use httpOnly cookies)
   - Check for XSS vulnerabilities
   - Verify no sensitive data in URLs
   - Test protected routes
   - Ensure API calls include auth headers

2. Backend security
   - Verify all endpoints have auth
   - Test role-based access
   - Check input validation
   - Review error messages (no info leakage)
   - Test rate limiting

**Afternoon: UX Polish**
1. Loading states everywhere
2. Error handling with user-friendly messages
3. Success notifications
4. Confirm dialogs for destructive actions
5. Empty states with helpful messages
6. Responsive design verification

**Evening: Documentation**
1. README with setup instructions
2. API documentation
3. Environment variables documentation
4. Known issues and future improvements

---

### Testing Checklist

#### Authentication
- [ ] User can register with valid data
- [ ] Registration rejects duplicate email
- [ ] Registration validates password strength
- [ ] User can login with correct credentials
- [ ] Login fails with wrong password
- [ ] JWT tokens are generated correctly
- [ ] Refresh token rotation works
- [ ] Logout revokes tokens
- [ ] Protected endpoints require authentication

#### Authorization
- [ ] Users can only see their assigned tasks
- [ ] Managers can see team tasks
- [ ] Admins can see all tasks
- [ ] Non-managers cannot create teams
- [ ] Users cannot delete others' tasks
- [ ] Role middleware properly restricts access

#### Security
- [ ] Passwords are hashed in database
- [ ] Tokens expire correctly
- [ ] Rate limiting prevents brute force
- [ ] CORS allows only frontend domain
- [ ] Security headers are present
- [ ] File uploads validate type and size
- [ ] No sensitive data in error messages

#### Functionality
- [ ] Tasks can be created and assigned
- [ ] Task status can be updated
- [ ] Teams can be created and managed
- [ ] Pagination works correctly
- [ ] Filtering returns correct results
- [ ] Optimistic updates work

---

## Additional Resources

### Documentation
- TypeScript: https://www.typescriptlang.org/docs/
- Express: https://expressjs.com/
- Mongoose: https://mongoosejs.com/docs/
- React: https://react.dev/
- Redux Toolkit: https://redux-toolkit.js.org/
- React Query: https://tanstack.com/query/latest

### Security Resources
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- JWT Best Practices: https://tools.ietf.org/html/rfc8725
- Node.js Security Checklist: https://cheatsheetseries.owasp.org/

### Best Practices
- Clean Code principles
- SOLID principles
- RESTful API design
- Git workflow (feature branches, meaningful commits)

---

## Success Criteria

By the end of this plan, your colleague should be able to:

✅ Build a secure REST API with TypeScript
✅ Implement JWT authentication with refresh tokens
✅ Create role-based authorization systems
✅ Use middleware effectively for cross-cutting concerns
✅ Build React applications with proper state management
✅ Integrate Redux Toolkit and React Query appropriately
✅ Implement frontend security best practices
✅ Deploy a full-stack application
✅ Debug issues across the full stack
✅ Write clean, type-safe code
✅ Understand security implications of design decisions

## Daily Time Commitment
- Study: 2-3 hours
- Coding: 3-4 hours
- Review: 1 hour

**Total: 6-8 hours per day for 14 days**

Good luck! 🚀
