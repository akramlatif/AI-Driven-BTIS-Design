import { useState } from 'react';
import { useAuth } from '@/components/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Shield, Loader2 } from 'lucide-react';

interface LoginModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function LoginModal({ open, onOpenChange }: LoginModalProps) {
  const { login, isLoading } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    try {
      await login(username, password);
      onOpenChange(false);
      setUsername('');
      setPassword('');
    } catch (err: any) {
      setError(err.message || 'Login failed. Please try again.');
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[400px] bg-slate-900 border-slate-800">
        <DialogHeader>
          <div className="flex items-center gap-2 mb-2">
            <Shield className="h-6 w-6 text-cyan-500" />
            <DialogTitle className="text-xl">BTIS Login</DialogTitle>
          </div>
          <DialogDescription className="text-slate-400">
            Enter your credentials to access the SOC Dashboard
          </DialogDescription>
        </DialogHeader>
        
        <form onSubmit={handleSubmit} className="space-y-4 mt-4">
          {error && (
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-600/50 text-red-400 text-sm">
              {error}
            </div>
          )}
          
          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              className="bg-slate-800 border-slate-700"
              required
            />
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              className="bg-slate-800 border-slate-700"
              required
            />
          </div>
          
          <Button 
            type="submit" 
            className="w-full bg-cyan-600 hover:bg-cyan-700"
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Signing in...
              </>
            ) : (
              'Sign In'
            )}
          </Button>
          
          <p className="text-xs text-slate-500 text-center">
            Default: admin / admin123
          </p>
        </form>
      </DialogContent>
    </Dialog>
  );
}
