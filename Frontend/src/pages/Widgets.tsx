import { Layout } from "@/components/Layout";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { useWidgets } from "@/context/WidgetContext";

const widgetList = [
  { id: "recentTransactions", name: "Recent Transactions" },
  { id: "income", name: "Income" },
  { id: "expenditure", name: "Expenditure" },
  { id: "investments", name: "Investments" },
  { id: "savings", name: "Savings" },
  { id: "expenseTrends", name: "Monthly / Weekly / Yearly Expenses" },
  { id: "financialGoals", name: "Financial Goals" },
  { id: "balanceOverview", name: "Balance & Monthly Expenditure Summary" },
  { id: "creditScore", name: "Credit Score" },
  { id: "lucentCircle", name: "Lucent Circle Widget" },
];

export default function Widgets() {
  const { widgets, toggleWidget } = useWidgets(); // ✅ Global widget state

  return (
    <Layout>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-foreground mb-2">Widget Manager</h1>
        <p className="text-muted-foreground">
          Choose which widgets appear on your financial dashboard.
        </p>
      </div>

      <div className="grid gap-4 max-w-2xl">
        {widgetList.map((widget) => (
          <Card
            key={widget.id}
            className="flex items-center justify-between p-4 border-border bg-card hover:border-primary/40 transition-all"
          >
            <div>
              <h2 className="text-lg font-semibold">{widget.name}</h2>
              <p className="text-sm text-muted-foreground">
                {widgets[widget.id]
                  ? "Visible on Dashboard"
                  : "Hidden from Dashboard"}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Label htmlFor={widget.id}>Enabled</Label>
              <Switch
                id={widget.id}
                checked={widgets[widget.id]}
                onCheckedChange={() => toggleWidget(widget.id)}
              />
            </div>
          </Card>
        ))}
      </div>
    </Layout>
  );
}
