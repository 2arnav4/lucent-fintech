import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useToast } from '@/hooks/use-toast';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '@/lib/api';

interface User {
  id: number;
  email: string;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  signin: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string) => Promise<void>;
  signout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();
  const navigate = useNavigate();

  useEffect(() => {
    // Check for existing token and validate it
    const checkAuth = async () => {
      const token = localStorage.getItem('token');
      if (token) {
        try {
          // You might want to add a /validate-token endpoint to your backend
          setUser({ id: 1, email: localStorage.getItem('userEmail') || '' });
        } catch (error) {
          localStorage.removeItem('token');
          localStorage.removeItem('userEmail');
        }
      }
      setIsLoading(false);
    };
    checkAuth();
  }, []);

  const signin = async (email: string, password: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        throw new Error('Invalid credentials');
      }

      const { token } = await response.json();
      localStorage.setItem('token', token);
      localStorage.setItem('userEmail', email);
      setUser({ id: 1, email });
      
      toast({
        title: 'Welcome back!',
        description: 'Successfully signed in',
      });
      
      navigate('/dashboard');
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Invalid email or password',
        variant: 'destructive',
      });
      throw error;
    }
  };

  const signup = async (email: string, password: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        throw new Error('Signup failed');
      }

      const { token } = await response.json();
      localStorage.setItem('token', token);
      localStorage.setItem('userEmail', email);
      setUser({ id: 1, email });
      
      toast({
        title: 'Welcome!',
        description: 'Account created successfully',
      });
      
      navigate('/onboarding');
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to create account',
        variant: 'destructive',
      });
      throw error;
    }
  };

  const signout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userEmail');
    setUser(null);
    navigate('/');
    toast({
      title: 'Signed out',
      description: 'Successfully signed out',
    });
  };

  return (
    <AuthContext.Provider value={{ 
      user, 
      isLoading, 
      isAuthenticated: !!user, 
      signin, 
      signup, 
      signout 
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}