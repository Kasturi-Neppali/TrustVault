import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import AuditTrail from './components/AuditTrail';

function App() {
  const [user, setUser] = useState(null);

  // Check if user is already logged in when the app loads
  useEffect(() => {
    const savedUser = localStorage.getItem('trustvault_user');
    const token = localStorage.getItem('trustvault_token');
    
    if (savedUser && token) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const handleLoginSuccess = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('trustvault_token');
    localStorage.removeItem('trustvault_user');
    setUser(null);
  };

  // If there is no user, show the Login screen
  if (!user) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  // If there is a user, show the Dashboard (placeholder for now)
  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-7xl mx-auto bg-white rounded-lg shadow-sm p-6">
        <div className="flex justify-between items-center mb-8 border-b pb-4">
          <h1 className="text-2xl font-bold text-gray-800">TrustVault Dashboard</h1>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600">
              Logged in as: <strong className="text-gray-900">{user.email}</strong> ({user.role})
            </span>
            <button 
              onClick={handleLogout}
              className="px-4 py-2 text-sm text-red-600 border border-red-200 rounded-md hover:bg-red-50 transition-colors"
            >
              Sign out
            </button>
          </div>
        </div>
        
        {/* Render the new Dashboard component here */}
        <Dashboard user={user} />

        {/* Conditionally render the Audit Trail if the user is an Admin */}
        {user.role === 'admin' && <AuditTrail />}
      </div>
    </div>
  );
}

export default App;
