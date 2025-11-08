import { useState } from "react";
import { ChevronDown, Plus, Bell, Sparkles } from "lucide-react";
import { Button } from "./ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";

export const TopNav = () => {
  const [timePeriod, setTimePeriod] = useState("This Month");
  const [aiInsightsActive, setAiInsightsActive] = useState(true);

  return (
    <header className="h-16 border-b border-border flex items-center justify-between px-6 lg:px-8 bg-card/50 backdrop-blur-sm">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="gap-2">
            {timePeriod}
            <ChevronDown className="w-4 h-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="bg-popover border-border">
          <DropdownMenuItem onClick={() => setTimePeriod("This Week")}>
            This Week
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setTimePeriod("This Month")}>
            This Month
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setTimePeriod("This Quarter")}>
            This Quarter
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setTimePeriod("This Year")}>
            This Year
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <div className="flex items-center gap-4">
        <Button
          variant={aiInsightsActive ? "default" : "outline"}
          size="sm"
          className="gap-2"
          onClick={() => setAiInsightsActive(!aiInsightsActive)}
        >
          <Sparkles className="w-4 h-4" />
          AI Insights {aiInsightsActive && "Active"}
        </Button>

        <Button variant="ghost" size="icon">
          <Plus className="w-5 h-5" />
        </Button>

        <Button variant="ghost" size="icon">
          <Bell className="w-5 h-5" />
        </Button>

        <div className="w-8 h-8 rounded-full bg-gradient-violet flex items-center justify-center text-sm font-semibold">
          IR
        </div>
      </div>
    </header>
  );
};
