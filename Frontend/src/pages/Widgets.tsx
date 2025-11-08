// src/pages/Widgets.tsx
import { Layout } from "@/components/Layout";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { useWidgets } from "@/context/WidgetContext";

const widgetList: { id: any; name: string; description?: string }[] = [
  { id: "netWorth", name: "Net Worth", description: "Total assets minus liabilities" },
  { id: "recentTransactions", name: "Recent Transactions", description: "Latest debits & credits" },
  { id: "income", name: "Income", description: "All income sources" },
  { id: "expenditure", name: "Expenditure", description: "Personal outgoing spend" },
  { id: "investments", name: "Investments", description: "Stocks, mutual funds, FDs etc." },
  { id: "savings", name: "Savings", description: "Your saved money" },
  { id: "monthlyWeeklyYearly", name: "Monthly / Weekly / Yearly Expenses", description: "Period-based breakdowns" },
  { id: "financialGoals", name: "Financial Goals", description: "Goals & progress" },
  { id: "creditScore", name: "Credit Score", description: "Your credit health" },
  { id: "lucentCircle", name: "Lucent Circle Widget", description: "Shared-expense groups" },
  { id: "monthlyBudget", name: "Monthly Budget", description: "Category budgets & progress" },
  { id: "savingsGoals", name: "Savings Goals", description: "Emergency, vacation goals" },
  { id: "aiInsights", name: "AI Insights", description: "Automated tips & alerts" },
];

export default function WidgetsPage() {
  const { widgets, toggleWidget } = useWidgets();

  return (
    <Layout>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-foreground mb-2">Widget Manager</h1>
        <p className="text-muted-foreground">Choose which widgets appear on your dashboard.</p>
      </div>

      <div className="grid gap-4 max-w-2xl">
        {widgetList.map((w) => (
          <Card
            key={w.id}
            className="flex items-center justify-between p-4 border-border bg-card hover:border-primary/40 transition-all"
          >
            <div>
              <h2 className="text-lg font-semibold">{w.name}</h2>
              <p className="text-sm text-muted-foreground">{w.description}</p>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-sm text-muted-foreground">Enabled</div>
              <Switch
                id={w.id}
                checked={!!widgets[w.id]}
                onCheckedChange={(val) => toggleWidget(w.id, Boolean(val))}
              />
            </div>
          </Card>
        ))}
      </div>
    </Layout>
  );
}
