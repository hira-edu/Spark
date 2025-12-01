import React, { useState, useEffect } from 'react';
import { Form, Input, Button, Alert, Progress } from 'antd';
import { UserOutlined, LockOutlined, MailOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './login.css';

const SetupPage = () => {
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);
    const [passwordStrength, setPasswordStrength] = useState(0);
    const navigate = useNavigate();
    const { initialSetup, needsSetup, isAuthenticated } = useAuth();

    useEffect(() => {
        // If already authenticated, redirect to home
        if (isAuthenticated) {
            navigate('/', { replace: true });
        }
        // If setup is not needed, redirect to login
        if (!needsSetup) {
            navigate('/login', { replace: true });
        }
    }, [isAuthenticated, needsSetup, navigate]);

    const calculatePasswordStrength = (password) => {
        if (!password) return 0;

        let strength = 0;

        // Length
        if (password.length >= 8) strength += 25;
        if (password.length >= 12) strength += 25;

        // Complexity
        if (/[a-z]/.test(password)) strength += 10;
        if (/[A-Z]/.test(password)) strength += 15;
        if (/[0-9]/.test(password)) strength += 15;
        if (/[^a-zA-Z0-9]/.test(password)) strength += 10;

        return Math.min(strength, 100);
    };

    const getPasswordStrengthColor = (strength) => {
        if (strength < 40) return '#ef4444';
        if (strength < 70) return '#f59e0b';
        return '#22c55e';
    };

    const getPasswordStrengthText = (strength) => {
        if (strength === 0) return '';
        if (strength < 40) return 'Weak';
        if (strength < 70) return 'Medium';
        return 'Strong';
    };

    const onPasswordChange = (e) => {
        const password = e.target.value;
        const strength = calculatePasswordStrength(password);
        setPasswordStrength(strength);
    };

    const onFinish = async (values) => {
        setError('');
        setLoading(true);

        try {
            const result = await initialSetup(
                values.username,
                values.password,
                values.email
            );

            if (result.success) {
                setSuccess(true);
                // Redirect to login after 2 seconds
                setTimeout(() => {
                    navigate('/login', { replace: true });
                }, 2000);
            } else {
                setError(result.message || 'Setup failed. Please try again.');
            }
        } catch (err) {
            console.error('Setup error:', err);
            setError('An error occurred during setup. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const onFinishFailed = () => {
        setError('Please check your input and try again.');
    };

    if (success) {
        return (
            <div className="login-container">
                <div className="login-card">
                    <div className="login-header">
                        <CheckCircleOutlined
                            style={{
                                fontSize: 64,
                                color: '#22c55e',
                                marginBottom: 16
                            }}
                        />
                        <h2 className="login-title">Setup Complete!</h2>
                        <p className="login-subtitle">
                            Your admin account has been created successfully.
                        </p>
                        <p className="login-subtitle" style={{ marginTop: 16 }}>
                            Redirecting to login...
                        </p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="login-container">
            <div className="login-card">
                <div className="login-header">
                    <h1 className="login-logo">Rocket</h1>
                    <h2 className="login-title">Initial Setup</h2>
                    <p className="login-subtitle">
                        Create your administrator account to get started
                    </p>
                </div>

                {error && (
                    <Alert
                        message={error}
                        type="error"
                        showIcon
                        closable
                        onClose={() => setError('')}
                        style={{ marginBottom: 24 }}
                    />
                )}

                <Alert
                    message="First-Time Setup"
                    description="No users found. Please create the first administrator account."
                    type="info"
                    showIcon
                    style={{ marginBottom: 24 }}
                />

                <Form
                    form={form}
                    name="setup"
                    className="login-form"
                    onFinish={onFinish}
                    onFinishFailed={onFinishFailed}
                    autoComplete="off"
                >
                    <Form.Item
                        name="username"
                        rules={[
                            {
                                required: true,
                                message: 'Please enter a username'
                            },
                            {
                                min: 3,
                                message: 'Username must be at least 3 characters'
                            },
                            {
                                pattern: /^[a-zA-Z0-9_-]+$/,
                                message: 'Username can only contain letters, numbers, - and _'
                            }
                        ]}
                    >
                        <Input
                            prefix={<UserOutlined />}
                            placeholder="Admin Username"
                            size="large"
                            autoComplete="username"
                            autoFocus
                        />
                    </Form.Item>

                    <Form.Item
                        name="email"
                        rules={[
                            {
                                type: 'email',
                                message: 'Please enter a valid email address'
                            }
                        ]}
                    >
                        <Input
                            prefix={<MailOutlined />}
                            placeholder="Email (optional)"
                            size="large"
                            autoComplete="email"
                        />
                    </Form.Item>

                    <Form.Item
                        name="password"
                        rules={[
                            {
                                required: true,
                                message: 'Please enter a password'
                            },
                            {
                                min: 6,
                                message: 'Password must be at least 6 characters'
                            }
                        ]}
                    >
                        <Input.Password
                            prefix={<LockOutlined />}
                            placeholder="Password"
                            size="large"
                            autoComplete="new-password"
                            onChange={onPasswordChange}
                        />
                    </Form.Item>

                    {passwordStrength > 0 && (
                        <div style={{ marginTop: -16, marginBottom: 24 }}>
                            <Progress
                                percent={passwordStrength}
                                strokeColor={getPasswordStrengthColor(passwordStrength)}
                                showInfo={false}
                                size="small"
                            />
                            <div className="password-strength-text">
                                Password Strength: {getPasswordStrengthText(passwordStrength)}
                            </div>
                        </div>
                    )}

                    <Form.Item
                        name="confirmPassword"
                        dependencies={['password']}
                        rules={[
                            {
                                required: true,
                                message: 'Please confirm your password'
                            },
                            ({ getFieldValue }) => ({
                                validator(_, value) {
                                    if (!value || getFieldValue('password') === value) {
                                        return Promise.resolve();
                                    }
                                    return Promise.reject(new Error('Passwords do not match'));
                                },
                            }),
                        ]}
                    >
                        <Input.Password
                            prefix={<LockOutlined />}
                            placeholder="Confirm Password"
                            size="large"
                            autoComplete="new-password"
                        />
                    </Form.Item>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            className="login-button"
                            loading={loading}
                            disabled={loading}
                        >
                            {loading ? 'Creating Account...' : 'Create Admin Account'}
                        </Button>
                    </Form.Item>
                </Form>

                <div className="login-footer">
                    <p>Rocket Remote Management System</p>
                    <p style={{ marginTop: 8, fontSize: 12 }}>
                        Your data is encrypted and secure
                    </p>
                </div>
            </div>
        </div>
    );
};

export default SetupPage;
