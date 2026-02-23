import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Filter } from 'lucide-react';

interface FilterDropdownProps {
  severityFilter: string;
  onSeverityChange: (value: string) => void;
  statusFilter: string;
  onStatusChange: (value: string) => void;
}

export function FilterDropdown({ 
  severityFilter, 
  onSeverityChange, 
  statusFilter, 
  onStatusChange 
}: FilterDropdownProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" className="gap-2">
          <Filter className="h-4 w-4" />
          Filter
          {(severityFilter !== 'all' || statusFilter !== 'all') && (
            <span className="ml-1 w-2 h-2 rounded-full bg-cyan-500" />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-48 bg-slate-900 border-slate-800">
        <DropdownMenuLabel>Severity</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={severityFilter} onValueChange={onSeverityChange}>
          <DropdownMenuRadioItem value="all">All</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="critical">Critical</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="high">High</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="medium">Medium</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="low">Low</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
        
        <DropdownMenuSeparator />
        
        <DropdownMenuLabel>Status</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={statusFilter} onValueChange={onStatusChange}>
          <DropdownMenuRadioItem value="all">All</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="new">New</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="acknowledged">Acknowledged</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="investigating">Investigating</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="resolved">Resolved</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
