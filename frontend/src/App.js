// src/App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

function Login() {
  return (
    <div className="login-container">
      <h2>Login to IRSSH Panel</h2>
      <form>
        <input type="text" placeholder="Username" />
        <input type="password" placeholder="Password" />
        <button type="submit">Login</button>
      </form>
    </div>
  );
}

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<div>IRSSH Panel</div>} />
      </Routes>
    </Router>
  );
}

export default App;
