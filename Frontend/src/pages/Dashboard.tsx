// src/pages/Dashboard.tsx
import { Layout } from "@/components/Layout";
import { NetWorthWidget } from "@/components/widgets/NetWorthWidget";
import { TransactionsWidget } from "@/components/widgets/TransactionsWidget";
import { BudgetWidget } from "@/components/widgets/BudgetWidget";
import { SavingsGoalsWidget } from "@/components/widgets/SavingsGoalsWidget";
import { AIInsightsWidget } from "@/components/widgets/AIInsightsWidget";
import { useWidgets } from "@/context/WidgetContext";

const Dashboard = () => {
  const { widgets } = useWidgets();

  return (
    <Layout>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-foreground mb-2">Financial Dashboard</h1>
        <p className="text-muted-foreground">Track and manage your finances in real-time</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 animate-fade-in">
        {widgets.netWorth && (
          // make NetWorth span full width on large screens if you want it bigger:
          <div className="lg:col-span-1">
            <NetWorthWidget />
          </div>
        )}

        {widgets.recentTransactions && (
          <div className="lg:col-span-1">
            <TransactionsWidget />
          </div>
        )}

        {widgets.monthlyBudget && (
          <div className="lg:col-span-1">
            <BudgetWidget />
          </div>
        )}

        {widgets.savingsGoals && (
          <div className="lg:col-span-1">
            <SavingsGoalsWidget />
          </div>
        )}

        {widgets.aiInsights && (
          <div className="lg:col-span-2">
            <AIInsightsWidget />
          </div>
        )}

        {/* add conditional slots for income, expenditure, investments, etc. where needed */}
      </div>
    </Layout>
  );
};

export default Dashboard;
