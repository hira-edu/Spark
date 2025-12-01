import React, { useState, useEffect } from 'react';
import { Form, Input, Button, Checkbox, Alert } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './login.css';

const LoginPage = () => {
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [remember, setRemember] = useState(() => {
        return localStorage.getItem('rocket-remember-me') === 'true';
    });
    const navigate = useNavigate();
    const location = useLocation();
    const { login, isAuthenticated, needsSetup } = useAuth();

    // Get the redirect path from location state, default to home
    const from = location.state?.from?.pathname || '/';

    useEffect(() => {
        // Prefill remembered username
        const rememberedUsername = localStorage.getItem('rocket-remember-username');
        form.setFieldsValue({
            username: rememberedUsername || undefined,
            remember
        });
        // If already authenticated, redirect
        if (isAuthenticated) {
            navigate(from, { replace: true });
        }
        // If setup is needed, redirect to setup page
        if (needsSetup) {
            navigate('/setup', { replace: true });
        }
    }, [isAuthenticated, needsSetup, navigate, from, form]);

    const normalizeError = (message) => {
        if (!message) return 'Invalid username or password';
        if (
            message.includes('AUTH.INVALID_CREDENTIALS') ||
            message.includes('INVALID_CREDENTIALS') ||
            message.includes('AUTH.INVALID_CREDENTIALS')
        ) {
            return 'Invalid username or password';
        }
        return message;
    };

    const onFinish = async (values) => {
        setError('');
        setLoading(true);

        try {
            const result = await login(values.username, values.password);

            if (result.success) {
                if (remember) {
                    localStorage.setItem('rocket-remember-me', 'true');
                    localStorage.setItem('rocket-remember-username', values.username);
                } else {
                    localStorage.removeItem('rocket-remember-me');
                    localStorage.removeItem('rocket-remember-username');
                }
                // Successful login - navigate to the page they tried to access or home
                navigate(from, { replace: true });
            } else {
                setError(normalizeError(result.message));
                form.setFieldsValue({ password: '' });
            }
        } catch (err) {
            console.error('Login error:', err);
            setError('An error occurred during login. Please try again.');
            form.setFieldsValue({ password: '' });
        } finally {
            setLoading(false);
        }
    };

    const onFinishFailed = () => {
        setError('Please check your input and try again.');
    };

    return (
        <div className="login-container">
            <div className="login-card">
                <div className="login-header">
                    <h1 className="login-logo">Rocket</h1>
                    <h2 className="login-title">Welcome Back</h2>
                    <p className="login-subtitle">Sign in to continue to your dashboard</p>
                </div>

                {error && (
                    <Alert
                        message={error}
                        type="error"
                        showIcon
                        closable
                        role="alert"
                        onClose={() => setError('')}
                        style={{ marginBottom: 24 }}
                    />
                )}

                <Form
                    form={form}
                    name="login"
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
                                message: 'Please enter your username'
                            },
                            {
                                min: 3,
                                message: 'Username must be at least 3 characters'
                            }
                        ]}
                    >
                        <Input
                            prefix={<UserOutlined />}
                            placeholder="Username"
                            size="large"
                            autoComplete="username"
                            autoFocus
                            disabled={loading}
                        />
                    </Form.Item>

                    <Form.Item
                        name="password"
                        rules={[
                            {
                                required: true,
                                message: 'Please enter your password'
                            }
                        ]}
                    >
                        <Input.Password
                            prefix={<LockOutlined />}
                            placeholder="Password"
                            size="large"
                            autoComplete="current-password"
                            disabled={loading}
                        />
                    </Form.Item>

                    <Form.Item>
                        <Form.Item name="remember" valuePropName="checked" noStyle initialValue={remember}>
                            <Checkbox
                                onChange={(e) => {
                                    setRemember(e.target.checked);
                                    form.setFieldsValue({ remember: e.target.checked });
                                }}
                                disabled={loading}
                            >
                                Remember me
                            </Checkbox>
                        </Form.Item>
                    </Form.Item>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            className="login-button"
                            loading={loading}
                            disabled={loading}
                        >
                            {loading ? 'Signing In...' : 'Sign In'}
                        </Button>
                    </Form.Item>
                </Form>

                <div className="login-footer">
                    <p>Rocket Remote Management System</p>
                    <p style={{ marginTop: 8, fontSize: 12 }}>
                        Secure • Fast • Reliable
                    </p>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
