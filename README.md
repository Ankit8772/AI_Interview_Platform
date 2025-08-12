# 🎯 AI Interview Platform

An **AI-powered interview preparation platform** that helps users practice technical and behavioral interviews through **voice-based conversation**.  
The voice agent is powered by **[VAPI](https://vapi.ai/)** for real-time speech recognition, natural language understanding, and conversational flow.  

🚀 **Live Demo:** [ai-interview-platform-flax.vercel.app](https://ai-interview-platform-flax.vercel.app/interview)

---

## 📌 Features

- 🎙 **Voice-Based Interviews** – Conduct realistic mock interviews with a conversational AI agent.
- 🧠 **AI-Powered Questioning** – Dynamic, context-aware questions tailored to the user's responses.
- 📊 **Performance Feedback** – Instant evaluation and suggestions for improvement.
- 🔒 **Authentication** – Secure sign-in/sign-up with persistent session storage.
- 📂 **Interview History** – Store and review past interviews for progress tracking.
- ☁ **Cloud Deployment** – Hosted on [Vercel](https://vercel.com/) for global accessibility.

---

## 🛠 Tech Stack

**Frontend**
- [Next.js 15](https://nextjs.org/) – React framework with App Router
- [Tailwind CSS](https://tailwindcss.com/) – Utility-first styling
- [ShadCN/UI](https://ui.shadcn.com/) – Reusable UI components

**Backend**
- [Firebase Firestore](https://firebase.google.com/docs/firestore) – NoSQL database
- [Next.js API Routes](https://nextjs.org/docs/api-routes/introduction) – Serverless functions
- [VAPI](https://vapi.ai/) – AI-powered voice agent API

**Other**
- TypeScript for type safety
- Serverless architecture on Vercel

---

## 📂 Project Structure

ai-interview-platform/
├── app/ # Next.js App Router pages
│ ├── interview/ # Interview-related routes
│ ├── sign-in/ # Authentication pages
│ ├── sign-up/
│ └── api/ # API routes (VAPI, Firestore)
├── lib/ # Shared utilities & actions
├── components/ # UI components
├── public/ # Static assets
└── README.md
