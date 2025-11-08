import { useState } from "react";
import { Target } from "lucide-react";
import { Card } from "../ui/card";
import { Progress } from "../ui/progress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../ui/dialog";

const goals = [
  { name: "Emergency Fund", current: 8200, target: 10000, color: "bg-success" },
  { name: "Vacation Fund", current: 2250, target: 5000, color: "bg-primary" },
  { name: "New Car", current: 4500, target: 15000, color: "bg-accent" },
];

export const SavingsGoalsWidget = () => {
  const [isHovered, setIsHovered] = useState(false);
  const [selectedGoal, setSelectedGoal] = useState(goals[0]);

  return (
    <Card
      className={`p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 ${
        isHovered ? "glow-violet" : ""
      }`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="flex items-center gap-2 mb-6">
        <Target className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-medium text-foreground">Savings Goals</h3>
      </div>

      <div className="space-y-4">
        {goals.map((goal) => {
          const percentage = (goal.current / goal.target) * 100;
          return (
            <Dialog key={goal.name}>
              <DialogTrigger asChild>
                <div
                  className="cursor-pointer hover:bg-muted/30 p-3 rounded-lg transition-all"
                  onClick={() => setSelectedGoal(goal)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-foreground">{goal.name}</span>
                    <span className="text-sm text-success">{Math.round(percentage)}%</span>
                  </div>
                  <Progress
                    value={percentage}
                    className="h-2 mb-1"
                    indicatorClassName={goal.color}
                  />
                  <div className="text-xs text-muted-foreground">
                    ${goal.current.toLocaleString()} of ${goal.target.toLocaleString()}
                  </div>
                </div>
              </DialogTrigger>
              <DialogContent className="bg-popover border-border">
                <DialogHeader>
                  <DialogTitle>{selectedGoal.name}</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">Current Progress</p>
                    <p className="text-3xl font-bold text-primary">
                      ${selectedGoal.current.toLocaleString()}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      of ${selectedGoal.target.toLocaleString()} goal
                    </p>
                  </div>
                  <Progress
                    value={(selectedGoal.current / selectedGoal.target) * 100}
                    className="h-3"
                    indicatorClassName={selectedGoal.color}
                  />
                  <div className="bg-muted/50 p-4 rounded-lg">
                    <p className="text-sm text-muted-foreground mb-1">Remaining</p>
                    <p className="text-xl font-semibold text-foreground">
                      ${(selectedGoal.target - selectedGoal.current).toLocaleString()}
                    </p>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          );
        })}
      </div>
    </Card>
  );
};
