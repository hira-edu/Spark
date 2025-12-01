import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Spin } from 'antd';
import { useAuth } from '../context/AuthContext';

const AuthGuard = ({ children }) => {
    const { isAuthenticated, loading, needsSetup } = useAuth();
    const location = useLocation();

    // Show loading spinner while checking authentication
    if (loading) {
        return (
            <div
                style={{
                    display: 'flex',
                    justifyContent: 'center',
                    alignItems: 'center',
                    minHeight: '100vh',
                    background: '#1a1a1a'
                }}
            >
                <Spin size="large" tip="Loading..." />
            </div>
        );
    }

    // If setup is needed, redirect to setup page
    if (needsSetup) {
        return <Navigate to="/setup" replace />;
    }

    // If not authenticated, redirect to login
    // Save the location they were trying to access
    if (!isAuthenticated) {
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    // User is authenticated, render the protected content
    return children;
};

export default AuthGuard;
