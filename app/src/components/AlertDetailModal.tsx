import { useState } from 'react';
import { alertsAPI } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { AlertTriangle, Clock, User, Activity, Loader2, Check, X } from 'lucide-react';

interface AlertItem {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  user: string;
  timestamp: string;
  status: string;
  risk_score: number;
  description?: string;
}

interface AlertDetailModalProps {
  alert: AlertItem | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onStatusChange?: () => void;
}

export function AlertDetailModal({ alert, open, onOpenChange, onStatusChange }: AlertDetailModalProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [actionType, setActionType] = useState<'ack' | 'resolve' | null>(null);

  if (!alert) return null;

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-green-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-500';
    if (score >= 50) return 'text-orange-500';
    if (score >= 25) return 'text-yellow-500';
    return 'text-green-500';
  };

  const handleAcknowledge = async () => {
    setIsLoading(true);
    setActionType('ack');
    try {
      await alertsAPI.acknowledge(alert.id);
      onStatusChange?.();
      onOpenChange(false);
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    } finally {
      setIsLoading(false);
      setActionType(null);
    }
  };

  const handleResolve = async () => {
    setIsLoading(true);
    setActionType('resolve');
    try {
      await alertsAPI.resolve(alert.id);
      onStatusChange?.();
      onOpenChange(false);
    } catch (err) {
      console.error('Failed to resolve alert:', err);
    } finally {
      setIsLoading(false);
      setActionType(null);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px] bg-slate-900 border-slate-800">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-orange-500" />
            <DialogTitle>Alert Details</DialogTitle>
          </div>
        </DialogHeader>
        
        <div className="space-y-4 mt-4">
          {/* Alert ID and Severity */}
          <div className="flex items-center justify-between">
            <span className="font-mono text-sm text-slate-400">{alert.id}</span>
            <Badge className={getSeverityColor(alert.severity)}>
              {alert.severity.toUpperCase()}
            </Badge>
          </div>
          
          {/* Title */}
          <div>
            <h3 className="text-lg font-semibold">{alert.title}</h3>
            <p className="text-sm text-slate-400 mt-1">
              {alert.description || 'Potential security threat detected based on behavioral analysis.'}
            </p>
          </div>
          
          {/* Info Grid */}
          <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-slate-800/50">
            <div className="flex items-center gap-2">
              <User className="h-4 w-4 text-slate-400" />
              <div>
                <p className="text-xs text-slate-400">User</p>
                <p className="font-medium">{alert.user}</p>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-slate-400" />
              <div>
                <p className="text-xs text-slate-400">Risk Score</p>
                <p className={`font-bold ${getRiskColor(alert.risk_score)}`}>
                  {alert.risk_score}
                </p>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-slate-400" />
              <div>
                <p className="text-xs text-slate-400">Detected</p>
                <p className="text-sm">{alert.timestamp}</p>
              </div>
            </div>
            
            <div>
              <p className="text-xs text-slate-400">Status</p>
              <Badge variant="outline" className="capitalize mt-1">
                {alert.status}
              </Badge>
            </div>
          </div>
          
          {/* Actions */}
          <div className="flex gap-2 pt-2">
            {alert.status !== 'acknowledged' && alert.status !== 'resolved' && (
              <Button 
                onClick={handleAcknowledge}
                disabled={isLoading}
                className="flex-1 bg-blue-600 hover:bg-blue-700"
              >
                {isLoading && actionType === 'ack' ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Check className="mr-2 h-4 w-4" />
                )}
                Acknowledge
              </Button>
            )}
            
            {alert.status !== 'resolved' && (
              <Button 
                onClick={handleResolve}
                disabled={isLoading}
                variant="outline"
                className="flex-1 border-green-600 text-green-500 hover:bg-green-600/20"
              >
                {isLoading && actionType === 'resolve' ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Check className="mr-2 h-4 w-4" />
                )}
                Resolve
              </Button>
            )}
            
            <Button 
              variant="ghost" 
              onClick={() => onOpenChange(false)}
              className="flex-1"
            >
              <X className="mr-2 h-4 w-4" />
              Close
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
