import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [needsSetup, setNeedsSetup] = useState(false);

    // Check if initial setup is needed
    const checkSetup = async () => {
        try {
            const res = await axios.get('/api/auth/setup/check');
            if (res.data.code === 0) {
                setNeedsSetup(res.data.data.needsSetup);
            }
        } catch (error) {
            console.error('Failed to check setup status:', error);
        }
    };

    // Check if user is already authenticated
    const checkAuth = async () => {
        try {
            const res = await axios.get('/api/auth/user');
            if (res.data.code === 0) {
                setUser(res.data.data.user);
            } else {
                setUser(null);
            }
        } catch (error) {
            setUser(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        const initAuth = async () => {
            await checkSetup();
            await checkAuth();
        };
        initAuth();
    }, []);

    const login = async (username, password) => {
        const res = await axios.post('/api/auth/login', {
            username,
            password
        });

        if (res.data.code === 0) {
            setUser(res.data.data.user);
            return { success: true };
        } else {
            return { success: false, message: res.data.msg };
        }
    };

    const logout = async () => {
        try {
            await axios.post('/api/auth/logout');
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            setUser(null);
        }
    };

    const initialSetup = async (username, password, email) => {
        const res = await axios.post('/api/auth/setup', {
            username,
            password,
            email
        });

        if (res.data.code === 0) {
            setNeedsSetup(false);
            return { success: true };
        } else {
            return { success: false, message: res.data.msg };
        }
    };

    const changePassword = async (oldPassword, newPassword) => {
        const res = await axios.post('/api/auth/password/change', {
            oldPassword,
            newPassword
        });

        if (res.data.code === 0) {
            return { success: true };
        } else {
            return { success: false, message: res.data.msg };
        }
    };

    // Check if session is still valid (for reconnection scenarios)
    const validateSession = async () => {
        try {
            const res = await axios.get('/api/auth/user');
            if (res.data.code === 0) {
                setUser(res.data.data.user);
                return true;
            }
            setUser(null);
            return false;
        } catch (error) {
            setUser(null);
            return false;
        }
    };

    const value = {
        user,
        loading,
        needsSetup,
        isAuthenticated: !!user,
        login,
        logout,
        initialSetup,
        changePassword,
        refreshAuth: checkAuth,
        validateSession,
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};
