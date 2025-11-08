import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { MoreVertical } from "lucide-react";

interface WidgetActionsProps {
  onEdit: () => void;
  onRefresh: () => void;
  onRemove: () => void;
}

export const WidgetActions = ({ onEdit, onRefresh, onRemove }: WidgetActionsProps) => {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="text-muted-foreground hover:text-foreground">
          <MoreVertical className="w-4 h-4" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="bg-popover border-border">
        <DropdownMenuItem onClick={onEdit}>Edit Widget</DropdownMenuItem>
        <DropdownMenuItem onClick={onRefresh}>Refresh Data</DropdownMenuItem>
        <DropdownMenuItem
          onClick={onRemove}
          className="text-destructive focus:text-destructive"
        >
          Remove Widget
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
