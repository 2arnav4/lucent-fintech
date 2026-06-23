import { useState } from "react";
import { Sparkles } from "lucide-react";
import { Card } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../ui/dialog";
import { API_BASE_URL } from "@/lib/api";

export const AIInsightsWidget = () => {
  const [query, setQuery] = useState("");
  const [insights, setInsights] = useState<any[]>([]);
  const [selectedInsight, setSelectedInsight] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerateInsight = async () => {
    setLoading(true);
    setError(null);

    try {
      const token = localStorage.getItem("token"); // JWT token from login/signup
      if (!token) throw new Error("User not authenticated");

      const response = await fetch(`${API_BASE_URL}/ai-insights`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ query }),
      });

      if (!response.ok) throw new Error("Failed to fetch insight");

      const data = await response.json();

      // Convert backend response to your UI format
      const newInsight = {
        title: `Insight for: ${query}`,
        description: data.insight,
        recommendation: "Use this insight to adjust your financial goals.",
        impact: "positive",
      };

      setInsights([newInsight, ...insights]);
      setQuery("");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 relative z-0">
      <div className="flex items-center gap-2 mb-4">
        <Sparkles className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-medium text-foreground">AI Insights</h3>
      </div>

      <div className="space-y-3">
        {/* Input to ask AI */}
        <div className="flex gap-2">
          <Input
            placeholder="Ask AI about your finances..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1"
          />
          <Button onClick={handleGenerateInsight} disabled={loading || !query}>
            {loading ? "Thinking..." : "Ask"}
          </Button>
        </div>

        {/* Error message */}
        {error && <p className="text-sm text-destructive">{error}</p>}

        {/* Empty state */}
        {insights.length === 0 && (
          <p className="text-sm text-muted-foreground mt-2">
            No insights yet — try asking something like:
            <br /> <i>“How can I optimize my investments this month?”</i>
          </p>
        )}

        {/* Generated insights */}
        {insights.map((insight, index) => (
          <Dialog key={index}>
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
                    <p className="text-xs text-muted-foreground line-clamp-2">
                      {insight.description}
                    </p>
                  </div>
                </div>
              </div>
            </DialogTrigger>
            <DialogContent className="bg-popover border-border">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-primary" />
                  {selectedInsight?.title}
                </DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Analysis</p>
                  <p className="text-foreground">{selectedInsight?.description}</p>
                </div>
                <div className="bg-primary/10 border border-primary/20 p-4 rounded-lg">
                  <p className="text-sm text-muted-foreground mb-2">💡 Recommendation</p>
                  <p className="text-foreground">{selectedInsight?.recommendation}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Impact:</span>
                  <span
                    className={`text-xs font-medium px-2 py-1 rounded-full ${
                      selectedInsight?.impact === "positive"
                        ? "bg-success/20 text-success"
                        : selectedInsight?.impact === "high"
                        ? "bg-destructive/20 text-destructive"
                        : "bg-primary/20 text-primary"
                    }`}
                  >
                    {selectedInsight?.impact}
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
