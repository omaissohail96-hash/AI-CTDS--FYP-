import React, { createContext, useContext, useState, useEffect } from 'react';
import API_BASE from '../config/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('token') || null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(!!token); // Loading only if we start with a token

  useEffect(() => {
    if (token) {
      localStorage.setItem('token', token);
      fetchUserProfile(token);
    } else {
      localStorage.removeItem('token');
      setUser(null);
      setLoading(false);
    }
  }, [token]);

  const fetchUserProfile = async (authToken) => {
    try {
      const response = await fetch(`${API_BASE}/rbac/my-permissions`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to fetch user profile');
      }

      const data = await response.json();
      setUser(data);
    } catch (error) {
      console.error('Auth error:', error);
      // Optional: Clear token if it's invalid
      setToken(null);
    } finally {
      setLoading(false);
    }
  };

  const login = (newToken) => {
    setLoading(true);
    setToken(newToken);
  };

  const logout = () => {
    setToken(null);
  };

  const hasRole = (roles) => {
    if (!user) return false;
    if (user.role === 'super_admin') return true;
    if (Array.isArray(roles)) {
      return roles.includes(user.role);
    }
    return user.role === roles;
  };

  const hasPermission = (permission) => {
    if (!user) return false;
    if (user.role === 'super_admin') return true;
    return user.permissions.includes(permission);
  };

  return (
    <AuthContext.Provider value={{
      token,
      user,
      loading,
      login,
      logout,
      hasRole,
      hasPermission,
      isAuthenticated: !!token && !!user
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
