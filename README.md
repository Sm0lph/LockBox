# 🔐 LockBox - Secure Password Manager v1.0

Welcome to **LockBox**, a secure, personal password manager I built from scratch as my graduation project for my Bachelor's degree in Cybersecurity. This application is designed to give users complete control over their password storage — with strong encryption, a clean user interface, and essential security features that reflect real-world standards.

---

## 🛡️ Why I Built LockBox

As someone passionate about cybersecurity, I wanted to challenge myself by building something practical and relevant which also turned out to be my graduation project — a password manager that prioritizes **security**, **privacy**, and **usability**. Every aspect of this project was carefully researched, tested, and implemented by me, from encryption algorithms to session management.

---

## 🚀 Features

✅ User Registration & Login with Hashed Master Password  
✅ Secure Dashboard to View & Manage Stored Passwords  
✅ AES-256 Encryption with Unique IV per Entry  
✅ Passwords Encrypted on Save & Decrypted on Demand  
✅ Random Password Generator with Strength Options  
✅ Session Timeout After 30 Minutes of Inactivity  
✅ Settings Page with MFA Option & "Delete All Data" Button  
✅ Smooth Frontend UI (HTML, CSS, JS) Integrated with Flask  
✅ SQLite Backend with SQLAlchemy ORM

---

## 🔐 Encryption & Security Highlights

- **AES-256-CBC** is used for encrypting each password, with a **unique IV per entry**
- Master passwords are **hashed using Argon2**
- An **AES key is derived using PBKDF2** from the master password and a random salt
- Session storage ensures **no encryption keys are stored on the server**
- **Access control checks** prevent unauthorized access to password entries

---

## 🖥️ Technologies Used

- **Backend:** Python, Flask, SQLAlchemy, SQLite  
- **Frontend:** HTML, CSS, JavaScript, Bootstrap  
- **Security:** CryptoJS (client-side AES), PBKDF2, SHA-256  
- **Hosting:** Planned for Azure App Service  
- **Development Tools:** DB Browser, Postman, VS Code


