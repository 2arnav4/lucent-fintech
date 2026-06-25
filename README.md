🌌 Lucent — Illuminate Your Finances

Lucent is a next-generation, AI-powered financial management platform that centralizes your entire financial life — banking, investments, crypto, budgeting, and group expenses — all in one place.

“Illuminate your finances. Empower your freedom.”

🚀 Overview

Most people want to achieve financial freedom by 30, but have no idea where their money goes.
They juggle between 6+ apps — one for banking, one for stocks, one for crypto, another for expenses — and still lack a single, unified picture of their finances.

Lucent fixes that.

Lucent is your personal financial command center — a dashboard that brings together all your money, insights, and goals in one clean, beautiful, intelligent place.

✨ Key Features
💰 Unified Financial Dashboard

View your entire financial life — bank balance, investments, crypto, real estate, and savings — all in one place.
Each section is represented through customizable widgets that you can add, remove, or rearrange to your liking.

📊 AI-Powered Financial Advisor

An integrated LLM-based assistant that gives you personalized insights:

How you’re spending, saving, and investing

Where to optimize your portfolio

How much to invest monthly to hit your FIRE number (Financial Independence, Retire Early)

🔥 FIRE Tracker

Lucent automatically calculates your FIRE Number — the investment target required to retire early and live off returns — and tracks your progress toward it.

💸 Lucent Circles

Split group expenses effortlessly.

Create circles for roommates, trips, or parties

Upload or scan bills using OCR (even from WhatsApp images!)

The AI detects who ordered what — non-veg, drinks, etc. — and splits bills fairly

Initially, members get notifications

Later, UPI integration enables direct payments

📈 Trends

Real-time updates from:

Stock markets (via Twelve Data or Finnhub APIs)

Crypto (via CoinGecko API)

Personalized market insights
All visualized beautifully in charts and graphs.

🧩 Widget Customization

Every user can customize their dashboard:

Add/remove widgets like Net Worth, Budget, Investments, Crypto Tracker, or Daily Financial Health

Click any widget to navigate to its dedicated page for detailed analytics

🧠 Daily Financial Health Widget

Shows how you’re performing financially today — income, expenses, savings rate — summarized as a daily financial wellness percentage.

🧱 Project Architecture
📂 Folder Structure
src/
 ├── components/
 │    ├── Layout.tsx
 │    ├── Sidebar.tsx
 │    ├── TopNav.tsx
 │    └── widgets/
 │         ├── NetWorthWidget.tsx
 │         ├── TransactionsWidget.tsx
 │         ├── BudgetWidget.tsx
 │         ├── SavingsGoalsWidget.tsx
 │         ├── AIInsightsWidget.tsx
 │         ├── InvestmentsWidget.tsx     ← NEW
 │         └── DailyHealthWidget.tsx     ← NEW
 ├── pages/
 │    ├── Dashboard.tsx
 │    ├── Analytics.tsx
 │    ├── Circles.tsx
 │    ├── Settings.tsx
 │    └── Trends.tsx                     ← NEW
 ├── hooks/
 │    ├── use-toast.ts
 │    ├── use-mobile.tsx
 │    └── use-widgets.ts                 ← NEW (manages user widget preferences)
 ├── lib/
 │    ├── utils.ts
 │    └── api/
 │         ├── investments.ts            ← NEW
 │         ├── crypto.ts                 ← NEW
 │         └── stocks.ts                 ← NEW

⚙️ Tech Stack
💻 Frontend

React 18 + TypeScript (with Vite)

Tailwind CSS for styling

Shadcn/UI for consistent, accessible UI components

Lucide React for icons

Recharts for analytics & financial visualizations

Framer Motion for smooth animations

React Query for API state management

🧠 Processing Layer

Local regex parser for offline billing extraction and smart local financial insights

Mock processing for reading bills and receipts

🧾 APIs & Data

CoinGecko API → Real-time crypto prices

Twelve Data / Finnhub → Stock market trends

Kite Connect (Zerodha) → Optional brokerage integration

Razorpay / Paytm UPI SDK → For future in-app settlements

🏗 Backend

Node.js + Express.js (TypeScript) — REST API layer

Prisma ORM + PostgreSQL — for users, transactions, circles, and widget configs

JWT Authentication (via Clerk or NextAuth)

Cloudinary / Firebase Storage for image uploads (bills, receipts)

☁️ Infrastructure

Vercel — hosting frontend + edge APIs

Railway / Render / Supabase — backend + database

GitHub Actions — CI/CD pipeline

Sentry — error monitoring

🔐 Security

AES-256 encrypted financial data

Role-based access control (RBAC)

HTTPS enforced with Cloudflare

Encrypted API keys (Vault/Env vars)

GDPR and RBI data compliance-ready

💾 Setup Guide
1️⃣ Clone the Repo
git clone https://github.com/w0nb0n/lucent-fintech.git
cd lucent-fintech

2️⃣ Install Dependencies
bun install   # or npm install / yarn install

3️⃣ Environment Variables

Create .env in the project root:

VITE_API_BASE_URL=http://localhost:5000
VITE_OPENAI_KEY=your_openai_key_here
VITE_COIN_GECKO_API=https://api.coingecko.com/api/v3
VITE_TWELVE_DATA_API_KEY=your_twelve_data_key

4️⃣ Run the App
bun run dev

5️⃣ Optional: Run Backend
cd backend
bun run start

🧮 API Endpoints (Backend Examples)
Endpoint	Method	Description
/api/investments	GET	Fetch user investments across sources
/api/crypto	GET	Fetch crypto portfolio and live prices
/api/stocks	GET	Fetch stock holdings and market trends
/api/circles	POST	Create or update group expenses
/api/fire-number	GET	Calculate user's FIRE number
/api/advice	POST	Generate AI-driven financial advice
🪄 Future Enhancements

🔗 Live UPI payment integration

🧾 Full OCR + WhatsApp Bill Parser

📱 Mobile App (React Native)

🧮 Predictive AI: “How much will I save next month?”

💬 Financial Chatbot: “Hey Lucent, how’s my portfolio today?”

💬 Vision

To make “financial freedom by 30” not a dream — but a default reality.
Lucent empowers young professionals to understand, track, and optimize their money — without juggling multiple apps, spreadsheets, or stress.
