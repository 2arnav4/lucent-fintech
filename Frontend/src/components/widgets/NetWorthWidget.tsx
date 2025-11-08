import { useState } from "react";
import { TrendingUp, Wallet, TrendingDown, Bitcoin, MoreVertical } from "lucide-react";
import { Card } from "../ui/card";
import { Button } from "../ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";

export const NetWorthWidget = () => {
  const [isHovered, setIsHovered] = useState(false);

  const categories = [
    { name: "Cash & Banking", value: "$47,231.80", icon: Wallet },
    { name: "Investments", value: "$82,645.52", icon: TrendingUp },
    { name: "Crypto", value: "$13,000.00", icon: Bitcoin },
  ];

  return (
    <Card
      className={`p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 ${
        isHovered ? "glow-violet" : ""
      }`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-2">
          <Wallet className="w-5 h-5 text-primary" />
          <h3 className="text-sm font-medium text-foreground">Net Worth</h3>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <MoreVertical className="w-4 h-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="bg-popover border-border">
            <DropdownMenuItem>Edit Widget</DropdownMenuItem>
            <DropdownMenuItem>Refresh Data</DropdownMenuItem>
            <DropdownMenuItem className="text-destructive">Remove Widget</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="mb-2">
        <p className="text-4xl font-bold text-primary">$142,847.32</p>
      </div>

      <div className="flex items-center gap-2 mb-6">
        <TrendingUp className="w-4 h-4 text-success" />
        <span className="text-sm text-success">+12.4% this month</span>
      </div>

      <div className="space-y-3">
        {categories.map((category) => (
          <div key={category.name} className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <category.icon className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">{category.name}</span>
            </div>
            <span className="text-sm font-medium text-foreground">{category.value}</span>
          </div>
        ))}
      </div>
    </Card>
  );
};
