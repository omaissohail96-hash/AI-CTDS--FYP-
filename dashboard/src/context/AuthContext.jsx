import React, { createContext, useContext, useState, useEffect } from 'react';
import API_BASE from '../config/api';
import { supabase } from '../config/supabaseClient';

const AuthContext = createContext(null);

const roleAliases = {
  super_admin: 'owner',
  workspace_admin: 'admin',
  security_analyst: 'analyst',
};

const normalizeRole = (role) => roleAliases[role] || role || 'viewer';

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('token') || null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(!!token); // Loading only if we start with a token

  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      // Only use Supabase token if we don't already have a backend token
      if (session && !localStorage.getItem('token')) {
        setToken(session.access_token);
        if (event === 'SIGNED_IN') {
          fetch(`${API_BASE}/me/record-login`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${session.access_token}` }
          }).catch((error) => console.warn('Google login tracking failed:', error));
        }
      }
    });

    return () => {
      subscription.unsubscribe();
    };
  }, []);

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
        if (response.status === 403) {
          const body = await response.json().catch(() => ({}));
          if (body.detail === 'Workspace access is pending owner approval.') {
            setUser({ user_id: '', email: '', role: 'pending', permissions: [] });
            return;
          }
        }
        throw new Error('Failed to fetch user profile');
      }

      const data = await response.json();
      setUser(data);
    } catch (error) {
      console.error('Auth error:', error);
      // Decode JWT locally so the app still works when the profile endpoint is unreachable
      try {
        const payload = JSON.parse(atob(authToken.split('.')[1]));
        setUser({
          user_id: payload.sub,
          role: 'workspace_admin',
          permissions: ['scans:create', 'scans:read', 'alerts:read', 'alerts:write'],
          email: '',
        });
      } catch {
        // Token is completely invalid — clear it
        setToken(null);
      }
    } finally {
      setLoading(false);
    }
  };

  const login = (newToken) => {
    setLoading(true);
    setToken(newToken);
  };

  const logout = async () => {
    await supabase.auth.signOut();
    setToken(null);
  };

  const hasRole = (roles) => {
    if (!user) return false;
    const role = normalizeRole(user.role);
    if (role === 'owner') return true;
    const allowed = Array.isArray(roles) ? roles : [roles];
    return allowed.map(normalizeRole).includes(role);
  };

  const hasPermission = (permission) => {
    if (!user) return false;
    if (normalizeRole(user.role) === 'owner') return true;
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
