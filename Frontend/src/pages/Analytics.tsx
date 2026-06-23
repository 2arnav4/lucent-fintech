import { useState } from "react";
import { Layout } from "@/components/Layout";
import { Card } from "@/components/ui/card";
import { API_BASE_URL } from "@/lib/api";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TrendingUp, IndianRupee, PiggyBank, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const Analytics = () => {
  const [query, setQuery] = useState("");
  const [insight, setInsight] = useState<string | null>(null);
  const [recommendation, setRecommendation] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Trends specific state
  const [symbols, setSymbols] = useState<string>("AAPL,MSFT");
  const [stocksLoading, setStocksLoading] = useState(false);
  const [stocksError, setStocksError] = useState<string | null>(null);
  const [stockData, setStockData] = useState<any | null>(null);

  const [cryptoLoading, setCryptoLoading] = useState(false);
  const [cryptoError, setCryptoError] = useState<string | null>(null);
  const [cryptoData, setCryptoData] = useState<any | null>(null);

  const handleFetchInsight = async () => {
    setLoading(true);
    setError(null);

    try {
      const token = localStorage.getItem("token");
      if (!token) throw new Error("No user token found — please log in first.");

      const response = await fetch(`${API_BASE_URL}/ai-insights`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ query }),
      });

      if (!response.ok) throw new Error("Failed to fetch AI insights");

      const data = await response.json();
      setInsight(data.insight || "No insight available right now.");
      setRecommendation(
        "This is an AI-generated suggestion based on your spending pattern."
      );
      setQuery("");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Fetch stock trends from backend
  const handleFetchStocks = async () => {
    setStocksLoading(true);
    setStocksError(null);
    setStockData(null);
    try {
      const resp = await fetch(
        `${API_BASE_URL}/trends/stocks?symbols=${encodeURIComponent(symbols)}`
      );
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body?.error || `Failed to fetch stocks: ${resp.status}`);
      }
      const data = await resp.json();
      setStockData(data);
    } catch (err: any) {
      setStocksError(err.message || "Error fetching stock trends");
    } finally {
      setStocksLoading(false);
    }
  };

  // Fetch crypto rates from backend
  const handleFetchCrypto = async () => {
    setCryptoLoading(true);
    setCryptoError(null);
    setCryptoData(null);
    try {
      const resp = await fetch(`${API_BASE_URL}/trends/crypto`);
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body?.error || `Failed to fetch crypto: ${resp.status}`);
      }
      const data = await resp.json();
      setCryptoData(data);
    } catch (err: any) {
      setCryptoError(err.message || "Error fetching crypto rates");
    } finally {
      setCryptoLoading(false);
    }
  };

  return (
    <Layout>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-2">Analytics</h1>
          <p className="text-muted-foreground">
            Visualize your financial trends and patterns
          </p>
        </div>
        <div className="flex items-center gap-4">
          <Select defaultValue="monthly">
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-popover border-border">
              <SelectItem value="weekly">Weekly</SelectItem>
              <SelectItem value="monthly">Monthly</SelectItem>
              <SelectItem value="yearly">Yearly</SelectItem>
            </SelectContent>
          </Select>

          <div className="flex items-center gap-2">
            <Input
              className="w-56"
              value={symbols}
              onChange={(e) => setSymbols(e.target.value)}
              placeholder="Symbols (comma separated)"
            />
            <Button onClick={handleFetchStocks} disabled={stocksLoading}>
              {stocksLoading ? "Loading..." : "Fetch Stocks"}
            </Button>
            <Button onClick={handleFetchCrypto} disabled={cryptoLoading} variant="outline">
              {cryptoLoading ? "Loading..." : "Fetch Crypto"}
            </Button>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <Card className="p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 hover:glow-violet">
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="text-sm text-muted-foreground mb-1">Net Worth</p>
              <p className="text-3xl font-bold text-foreground">₹142,847</p>
            </div>
            <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
              <IndianRupee className="w-6 h-6 text-primary" />
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm text-success">
            <TrendingUp className="w-4 h-4" />
            <span>+12.4% from last month</span>
          </div>
        </Card>

        <Card className="p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 hover:glow-violet">
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="text-sm text-muted-foreground mb-1">Monthly Expenses</p>
              <p className="text-3xl font-bold text-foreground">₹4,280</p>
            </div>
            <div className="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
              <TrendingUp className="w-6 h-6 text-destructive rotate-180" />
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm text-destructive">
            <TrendingUp className="w-4 h-4 rotate-180" />
            <span>+8.2% from last month</span>
          </div>
        </Card>

        <Card className="p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 hover:glow-violet">
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="text-sm text-muted-foreground mb-1">Savings Rate</p>
              <p className="text-3xl font-bold text-foreground">28%</p>
            </div>
            <div className="w-12 h-12 rounded-full bg-success/10 flex items-center justify-center">
              <PiggyBank className="w-6 h-6 text-success" />
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm text-success">
            <TrendingUp className="w-4 h-4" />
            <span>+3% from last month</span>
          </div>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card className="p-6 bg-card border-border">
          <h3 className="text-lg font-semibold text-foreground mb-6">
            Income vs Expenses
          </h3>
          <div className="h-64 flex items-end justify-around gap-4">
            {[65, 72, 58, 80, 75, 85].map((height, idx) => (
              <div key={idx} className="flex-1 flex flex-col items-center gap-2">
                <div className="w-full flex flex-col gap-1">
                  <div
                    className="w-full bg-primary/80 rounded-t transition-all duration-500 hover:bg-primary"
                    style={{ height: `${height}%` }}
                  />
                  <div
                    className="w-full bg-destructive/40 rounded-b transition-all duration-500 hover:bg-destructive/60"
                    style={{ height: `${100 - height}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground">
                  {["Jan", "Feb", "Mar", "Apr", "May", "Jun"][idx]}
                </span>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-6 bg-card border-border">
          <h3 className="text-lg font-semibold text-foreground mb-6">
            Expense Categories
          </h3>
          <div className="space-y-4">
            {[
              { name: "Housing", value: 42, color: "bg-primary" },
              { name: "Food & Dining", value: 21, color: "bg-violet-light" },
              { name: "Transportation", value: 15, color: "bg-accent" },
              { name: "Entertainment", value: 12, color: "bg-success" },
              { name: "Other", value: 10, color: "bg-muted" },
            ].map((category) => (
              <div key={category.name}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-foreground">{category.name}</span>
                  <span className="text-sm text-muted-foreground">{category.value}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className={`h-full ${category.color} transition-all duration-500`}
                    style={{ width: `${category.value}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* ✅ Dynamic AI Insights */}
      <Card className="p-6 bg-card border-border hover:glow-violet transition-all duration-300">
        <div className="flex items-center gap-2 mb-4">
          <Sparkles className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold text-foreground">
            AI Financial Summary
          </h3>
        </div>

        <div className="space-y-4">
          <div className="flex gap-2">
            <Input
              placeholder="Ask AI about your finances..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="flex-1"
            />
            <Button onClick={handleFetchInsight} disabled={loading || !query}>
              {loading ? "Thinking..." : "Ask"}
            </Button>
          </div>

          {error && <p className="text-destructive text-sm">{error}</p>}

          {insight ? (
            <>
              <p className="text-foreground">{insight}</p>
              <div className="bg-primary/10 border border-primary/20 p-4 rounded-lg">
                <p className="text-sm text-muted-foreground mb-2">
                  💡 Key Recommendation
                </p>
                <p className="text-foreground">{recommendation}</p>
              </div>
            </>
          ) : (
            <p className="text-sm text-muted-foreground">
              No AI summary yet — try asking something like{" "}
              <i>"How can I improve my spending this month?"</i>
            </p>
          )}
        </div>
      </Card>

      {/* Stocks Result */}
      <div className="mt-6">
        <Card className="p-4 bg-card border-border">
          <h3 className="text-lg font-medium mb-3">Stock Trends Response</h3>
          {stocksError && <p className="text-destructive">{stocksError}</p>}
          {!stockData && !stocksLoading && <p className="text-sm text-muted-foreground">No stock data loaded.</p>}
          {stocksLoading && <p className="text-sm">Loading stock trends...</p>}
          {stockData && (
            <pre className="text-xs whitespace-pre-wrap max-h-64 overflow-auto bg-muted/10 p-3 rounded">{JSON.stringify(stockData, null, 2)}</pre>
          )}
        </Card>
      </div>

      {/* Crypto Result */}
      <div className="mt-6">
        <Card className="p-4 bg-card border-border">
          <h3 className="text-lg font-medium mb-3">Crypto Rates Response</h3>
          {cryptoError && <p className="text-destructive">{cryptoError}</p>}
          {!cryptoData && !cryptoLoading && <p className="text-sm text-muted-foreground">No crypto data loaded.</p>}
          {cryptoLoading && <p className="text-sm">Loading crypto rates...</p>}
          {cryptoData && (
            <pre className="text-xs whitespace-pre-wrap max-h-64 overflow-auto bg-muted/10 p-3 rounded">{JSON.stringify(cryptoData, null, 2)}</pre>
          )}
        </Card>
      </div>
    </Layout>
  );
};

export default Analytics;
