import { useState, useMemo } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Sparkles } from "lucide-react";
import { API_BASE_URL } from "@/lib/api";

const currencyFormat = (value: number) => {
  try {
    return value.toLocaleString("en-IN", {
      style: "currency",
      currency: "INR",
      minimumFractionDigits: 2,
    });
  } catch {
    return value.toLocaleString();
  }
};

const getAuthToken = () =>
  localStorage.getItem("authToken") ||
  localStorage.getItem("token") ||
  null;

export default function FIREWidget() {
  const savedNet = Number(localStorage.getItem("netWorth") || "142847.32");
  const savedMonthly = Number(localStorage.getItem("monthlyExpenses") || "2500");

  const [netWorth, setNetWorth] = useState<number>(savedNet);
  const [monthlyExpenses, setMonthlyExpenses] = useState<number>(savedMonthly);
  const [savingsRate, setSavingsRate] = useState<number>(10);
  const [loading, setLoading] = useState(false);
  const [insight, setInsight] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isHovered, setIsHovered] = useState(false);

  const annualExpenses = useMemo(() => monthlyExpenses * 12, [monthlyExpenses]);
  const fireNumber = useMemo(() => annualExpenses * 25, [annualExpenses]);
  const annualSavings = useMemo(
    () => (monthlyExpenses * (savingsRate / 100)) * 12,
    [monthlyExpenses, savingsRate]
  );

  const yearsToFIRE = useMemo(() => {
    if (annualSavings <= 0) return Infinity;
    const remaining = Math.max(0, fireNumber - netWorth);
    return remaining / annualSavings;
  }, [fireNumber, netWorth, annualSavings]);

  const getFIREInsight = async () => {
    setLoading(true);
    setError(null);
    setInsight(null);

    const token = getAuthToken();
    const query = `Given a user with ₹${Math.round(netWorth).toLocaleString()} net worth, ₹${Math.round(
      monthlyExpenses
    ).toLocaleString()} monthly expenses, and a ${savingsRate}% savings rate, estimate how many years it would take to reach financial independence (FIRE number = annual expenses × 25). Suggest actionable financial strategies to reach FIRE faster.keep it under 80 words`;

    try {
      const res = await fetch(`${API_BASE_URL}/ai-insights`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ query }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.error || "Failed to fetch insight");
      }

      const data = await res.json();
      setInsight(data?.insight || "No insight received from LLM.");
    } catch (err: any) {
      setError(err.message || "Error fetching AI insight.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card
      className={`p-6 bg-card border-border transition-all duration-300 rounded-lg relative z-10 h-full ${
        isHovered ? "border-primary/50 shadow-[0_0_25px_rgba(139,92,246,0.25)]" : ""
      }`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="flex items-center gap-2 mb-6">
        <Sparkles className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-medium text-foreground">FIRE Calculator</h3>
      </div>

      <div className="space-y-4">
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">
            Net Worth (₹)
          </label>
          <Input
            type="number"
            value={netWorth}
            onChange={(e) => setNetWorth(Number(e.target.value || 0))}
          />
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1 block">
            Monthly Expenses (₹)
          </label>
          <Input
            type="number"
            value={monthlyExpenses}
            onChange={(e) => setMonthlyExpenses(Number(e.target.value || 0))}
          />
        </div>

        <div>
          <label className="text-xs text-muted-foreground mb-1 block">
            Savings Rate (%)
          </label>
          <Input
            type="number"
            value={savingsRate}
            onChange={(e) => setSavingsRate(Number(e.target.value || 0))}
          />
        </div>

        <div className="pt-2 text-sm space-y-1">
          <p>
            Annual Expenses:{" "}
            <span className="font-medium text-foreground">
              {currencyFormat(annualExpenses)}
            </span>
          </p>
          <p>
            FIRE Number (×25):{" "}
            <span className="font-medium text-foreground">
              {currencyFormat(fireNumber)}
            </span>
          </p>
          <p>
            Estimated Years to FIRE:{" "}
            <span className="font-medium text-foreground">
              {isFinite(yearsToFIRE)
                ? Math.max(0, Math.round(yearsToFIRE))
                : "—"}
            </span>
          </p>
        </div>

        <div className="flex gap-2 pt-4">
          <Button
            onClick={getFIREInsight}
            disabled={loading}
            className="flex-1 bg-primary text-white hover:bg-primary/90"
          >
            {loading ? "Thinking..." : "Get LLM Insight"}
          </Button>
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => {
              setNetWorth(savedNet);
              setMonthlyExpenses(savedMonthly);
              setSavingsRate(10);
              setInsight(null);
              setError(null);
            }}
          >
            Reset
          </Button>
        </div>

        {error && (
          <div className="text-sm text-destructive mt-3">{error}</div>
        )}

        {insight && (
          <div className="mt-4 text-sm bg-muted/30 border border-border/40 p-4 rounded-lg">
            <div className="font-medium mb-1 text-primary">💡 AI Insight</div>
            <div className="whitespace-pre-wrap text-xs text-foreground leading-relaxed">
              {insight}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
