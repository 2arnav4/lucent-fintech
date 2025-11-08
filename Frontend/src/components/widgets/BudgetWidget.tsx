import { useState } from "react";
import { PieChart, MoreVertical } from "lucide-react";
import { Card } from "../ui/card";
import { Button } from "../ui/button";
import { Progress } from "../ui/progress";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";

export const BudgetWidget = () => {
  const [isHovered, setIsHovered] = useState(false);

  const budgetCategories = [
    { name: "Housing", spent: 1800, budget: 2000 },
    { name: "Food & Dining", spent: 890, budget: 1000 },
    { name: "Transportation", spent: 420, budget: 600 },
    { name: "Entertainment", spent: 320, budget: 400 },
  ];

  const totalSpent = 4280;
  const totalBudget = 6000;
  const percentage = (totalSpent / totalBudget) * 100;

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
          <PieChart className="w-5 h-5 text-primary" />
          <h3 className="text-sm font-medium text-foreground">Monthly Budget</h3>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <MoreVertical className="w-4 h-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="bg-popover border-border">
            <DropdownMenuItem>Adjust Budget</DropdownMenuItem>
            <DropdownMenuItem>View History</DropdownMenuItem>
            <DropdownMenuItem className="text-destructive">Reset Budget</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <div className="mb-4">
        <div className="flex items-baseline justify-between mb-2">
          <span className="text-sm text-muted-foreground">
            ${totalSpent.toLocaleString()} of ${totalBudget.toLocaleString()}
          </span>
          <span className={`text-sm font-medium ${percentage > 80 ? "text-destructive" : "text-success"}`}>
            {Math.round(percentage)}%
          </span>
        </div>
        <Progress
          value={percentage}
          className="h-2"
          indicatorClassName={percentage > 80 ? "bg-destructive" : "bg-primary"}
        />
      </div>

      <div className="space-y-3">
        {budgetCategories.map((category) => (
          <div key={category.name} className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{category.name}</span>
            <span className="text-foreground font-medium">${category.spent}</span>
          </div>
        ))}
      </div>
    </Card>
  );
};
