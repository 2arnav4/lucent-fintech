import { Layout } from "@/components/Layout";
import { Card } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TrendingUp, DollarSign, PiggyBank, Sparkles } from "lucide-react";

const Analytics = () => {
  return (
    <Layout>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-2">Analytics</h1>
          <p className="text-muted-foreground">Visualize your financial trends and patterns</p>
        </div>
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
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <Card className="p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 hover:glow-violet">
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="text-sm text-muted-foreground mb-1">Net Worth</p>
              <p className="text-3xl font-bold text-foreground">$142,847</p>
            </div>
            <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
              <DollarSign className="w-6 h-6 text-primary" />
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
              <p className="text-3xl font-bold text-foreground">$4,280</p>
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <Card className="p-6 bg-card border-border">
          <h3 className="text-lg font-semibold text-foreground mb-6">Income vs Expenses</h3>
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
          <h3 className="text-lg font-semibold text-foreground mb-6">Expense Categories</h3>
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

      <Card className="p-6 bg-card border-border hover:glow-violet transition-all duration-300">
        <div className="flex items-center gap-2 mb-4">
          <Sparkles className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold text-foreground">AI Financial Summary</h3>
        </div>
        <div className="space-y-4">
          <p className="text-foreground">
            Your financial health is strong this month. You've successfully saved 28% of your
            income, exceeding your target by 3%. Your spending patterns show increased
            transportation costs, likely due to recent fuel price increases.
          </p>
          <div className="bg-primary/10 border border-primary/20 p-4 rounded-lg">
            <p className="text-sm text-muted-foreground mb-2">💡 Key Recommendation</p>
            <p className="text-foreground">
              Consider reviewing your subscription services. Our analysis shows $45/month in
              potentially unused subscriptions that could boost your savings by an additional
              $540 annually.
            </p>
          </div>
        </div>
      </Card>
    </Layout>
  );
};

export default Analytics;
