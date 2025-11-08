import { useState } from "react";
import { Sparkles } from "lucide-react";
import { Card } from "../ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../ui/dialog";

const insights = [
  {
    title: "Travel spending increased",
    description: "Your travel expenses rose 12% this week compared to last month's average.",
    recommendation: "Consider setting a travel budget to keep expenses in check.",
    impact: "medium",
  },
  {
    title: "Great savings progress",
    description: "You're on track to reach your Emergency Fund goal 2 months early!",
    recommendation: "Keep up the consistent monthly contributions.",
    impact: "positive",
  },
  {
    title: "Subscription check",
    description: "You have 3 unused subscriptions totaling $45/month.",
    recommendation: "Review and cancel unused subscriptions to save $540 annually.",
    impact: "high",
  },
];

export const AIInsightsWidget = () => {
  const [isHovered, setIsHovered] = useState(false);
  const [selectedInsight, setSelectedInsight] = useState(insights[0]);

  return (
    <Card
      className={`p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 ${
        isHovered ? "glow-violet animate-glow-pulse" : ""
      }`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="flex items-center gap-2 mb-4">
        <Sparkles className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-medium text-foreground">AI Insights</h3>
      </div>

      <div className="space-y-3">
        {insights.map((insight) => (
          <Dialog key={insight.title}>
            <DialogTrigger asChild>
              <div
                className="p-3 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-all border border-transparent hover:border-primary/30"
                onClick={() => setSelectedInsight(insight)}
              >
                <div className="flex items-start gap-2">
                  <div
                    className={`w-2 h-2 rounded-full mt-1.5 ${
                      insight.impact === "positive"
                        ? "bg-success"
                        : insight.impact === "high"
                        ? "bg-destructive"
                        : "bg-primary"
                    }`}
                  />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-foreground mb-1">{insight.title}</p>
                    <p className="text-xs text-muted-foreground">{insight.description}</p>
                  </div>
                </div>
              </div>
            </DialogTrigger>
            <DialogContent className="bg-popover border-border">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-primary" />
                  {selectedInsight.title}
                </DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Analysis</p>
                  <p className="text-foreground">{selectedInsight.description}</p>
                </div>
                <div className="bg-primary/10 border border-primary/20 p-4 rounded-lg">
                  <p className="text-sm text-muted-foreground mb-2">💡 Recommendation</p>
                  <p className="text-foreground">{selectedInsight.recommendation}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Impact:</span>
                  <span
                    className={`text-xs font-medium px-2 py-1 rounded-full ${
                      selectedInsight.impact === "positive"
                        ? "bg-success/20 text-success"
                        : selectedInsight.impact === "high"
                        ? "bg-destructive/20 text-destructive"
                        : "bg-primary/20 text-primary"
                    }`}
                  >
                    {selectedInsight.impact}
                  </span>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        ))}
      </div>
    </Card>
  );
};
