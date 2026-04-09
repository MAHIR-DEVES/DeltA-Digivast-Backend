# 🚀 DeltA Digivast – Backend

🌐 Live API: https://delt-a-digivast-backend.vercel.app/

---

## 📌 Project Overview

This is the backend server for **DeltA Digivast**, built with scalable
architecture.

It handles:

- Authentication & authorization
- Staff & office management
- Attendance tracking
- Salary system
- Blog & portfolio management
- Stripe payment system

---

## 🛠️ Tech Stack

- 🟢 Node.js
- 🚂 Express.js
- 🔷 TypeScript
- 🗄️ PostgreSQL
- 📦 pnpm (Package Manager)
- 🧱 Modular Architecture
- 🔐 JWT Authentication
- 💳 Stripe API

---

## ✨ Features

### 🔐 Authentication System

- JWT-based authentication
- Role-based authorization:
  - Admin
  - Manager
  - Employee

### 👥 User Management

- Create / update / delete staff
- Profile management
- Password change system

### ⏰ Attendance System

- Daily check-in & check-out
- Working hour tracking
- Login / logout tracking
- Monthly attendance reports

### 💰 Salary Management

- Salary tracking
- Payment status (Paid / Pending)

### 📊 Admin Dashboard

- Overview of:
  - Users
  - Attendance
  - Payments
  - Blogs
  - Projects

### 📝 Blog System

- Create / update / delete blogs

### 🎨 Portfolio Management

- Add / update / delete projects

### 📩 Lead Management

- Store contact form submissions

### 🎓 Course System

- Create and manage courses
- Track purchased courses

### 💳 Stripe Payment Integration

- Create checkout session
- Handle payment success
- Store payment data in database

---

## 🔑 Demo Credentials

### Admin

Email: admin@gmail.com  
Password: 12345678

### Manager

Email: manager@gmail.com  
Password: 12345678

### Employee

Email: employ@gmail.com  
Password: 12345678

---

## 📂 Project Setup

### 1️⃣ Clone repository

```bash
git clone https://github.com/MAHIR-DEVES/DeltA-Digivast-Backend
cd DeltA-Digivast-Backend

2️⃣ Install dependencies (pnpm)
pnpm install

3️⃣ Setup environment variables

Create .env file:

PORT=5000
NODE_ENV=development
DATABASE_URL=YourUrl
JWT_SECRET=YourJWT_SECRET

#
# CLIENT_URL=http://localhost:3000
# live
CLIENT_URL=https://delt-a-digivast-frontend.vercel.app

#
STRIPE_SECRET_KEY=Your_STRIPE_SECRET_KEY

STRIPE_WEBHOOK_SECRET=Your_STRIPE_WEBHOOK_SECRET
```

Run the project pnpm dev 5️⃣ Build for production pnpm build pnpm start
