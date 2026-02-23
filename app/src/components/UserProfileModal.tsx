import { useState } from 'react';
import { usersAPI, behaviorAPI } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { User, Activity, Clock, Flag, Loader2, Shield } from 'lucide-react';

interface UserRisk {
  id: number;
  username: string;
  risk_score: number;
  risk_level: string;
  last_activity: string;
  is_flagged: boolean;
  email?: string;
  department?: string;
}

interface UserProfileModalProps {
  user: UserRisk | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUserUpdate?: () => void;
}

export function UserProfileModal({ user, open, onOpenChange, onUserUpdate }: UserProfileModalProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [showTimeline, setShowTimeline] = useState(false);

  if (!user) return null;

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-500';
    if (score >= 50) return 'text-orange-500';
    if (score >= 25) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getProgressColor = (score: number) => {
    if (score >= 75) return 'bg-red-600';
    if (score >= 50) return 'bg-orange-500';
    if (score >= 25) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const handleToggleFlag = async () => {
    setIsLoading(true);
    try {
      await usersAPI.flag(user.id, !user.is_flagged, user.is_flagged ? 'Unflagged by analyst' : 'Flagged for investigation');
      onUserUpdate?.();
      onOpenChange(false);
    } catch (err) {
      console.error('Failed to toggle flag:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleViewTimeline = async () => {
    setIsLoading(true);
    try {
      const data = await behaviorAPI.getTimeline(user.id);
      setTimeline(data.timeline || []);
      setShowTimeline(true);
    } catch (err) {
      console.error('Failed to load timeline:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px] bg-slate-900 border-slate-800">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <User className="h-5 w-5 text-cyan-500" />
            <DialogTitle>User Profile</DialogTitle>
          </div>
        </DialogHeader>
        
        <div className="space-y-4 mt-4">
          {/* User Header */}
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-full bg-slate-700 flex items-center justify-center">
              <span className="text-xl font-medium">
                {user.username.split('.').map(n => n[0]).join('').toUpperCase()}
              </span>
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-semibold">{user.username}</h3>
                {user.is_flagged && (
                  <Badge variant="destructive">FLAGGED</Badge>
                )}
              </div>
              <p className="text-sm text-slate-400">User ID: {user.id}</p>
              {user.email && <p className="text-sm text-slate-400">{user.email}</p>}
            </div>
            <div className="text-right">
              <div className={`text-3xl font-bold ${getRiskColor(user.risk_score)}`}>
                {user.risk_score}
              </div>
              <p className="text-xs text-slate-400 capitalize">{user.risk_level} Risk</p>
            </div>
          </div>
          
          {/* Risk Score Progress */}
          <div className="p-4 rounded-lg bg-slate-800/50">
            <div className="flex justify-between text-sm mb-2">
              <span className="text-slate-400">Risk Score</span>
              <span className={getRiskColor(user.risk_score)}>{user.risk_score}/100</span>
            </div>
            <Progress value={user.risk_score} className={`h-3 ${getProgressColor(user.risk_score)}`} />
          </div>
          
          {/* Info Grid */}
          <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-slate-800/50">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-slate-400" />
              <div>
                <p className="text-xs text-slate-400">Last Activity</p>
                <p className="text-sm">{user.last_activity}</p>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-slate-400" />
              <div>
                <p className="text-xs text-slate-400">Risk Level</p>
                <p className="text-sm capitalize">{user.risk_level}</p>
              </div>
            </div>
          </div>
          
          {/* Timeline (if loaded) */}
          {showTimeline && timeline.length > 0 && (
            <div className="p-4 rounded-lg bg-slate-800/50 max-h-48 overflow-y-auto">
              <p className="text-xs font-medium text-slate-400 uppercase mb-2">Recent Activity</p>
              <div className="space-y-2">
                {timeline.slice(0, 5).map((item: any, idx: number) => (
                  <div key={idx} className="flex items-center gap-2 text-sm">
                    <Activity className="h-3 w-3 text-cyan-500" />
                    <span className="flex-1">{item.action || item.event_type}</span>
                    <span className="text-xs text-slate-500">{item.timestamp}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Actions */}
          <div className="flex gap-2 pt-2">
            <Button 
              onClick={handleViewTimeline}
              disabled={isLoading}
              variant="outline"
              className="flex-1"
            >
              {isLoading && !showTimeline ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Activity className="mr-2 h-4 w-4" />
              )}
              View Timeline
            </Button>
            
            <Button 
              onClick={handleToggleFlag}
              disabled={isLoading}
              className={`flex-1 ${user.is_flagged ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'}`}
            >
              {isLoading ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Flag className="mr-2 h-4 w-4" />
              )}
              {user.is_flagged ? 'Unflag User' : 'Flag User'}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
