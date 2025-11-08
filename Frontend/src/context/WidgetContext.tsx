import { createContext, useContext, useState, ReactNode } from "react";

interface WidgetState {
  [key: string]: boolean;
}

interface WidgetContextType {
  widgets: WidgetState;
  toggleWidget: (id: string) => void;
}

const defaultWidgets = {
  netWorth: true,
  recentTransactions: true,
  monthlyBudget: true,
  savingsGoals: true,
  aiInsights: true,
};

const WidgetContext = createContext<WidgetContextType | undefined>(undefined);

export const WidgetProvider = ({ children }: { children: ReactNode }) => {
  const [widgets, setWidgets] = useState<WidgetState>(defaultWidgets);

  const toggleWidget = (id: string) => {
    setWidgets((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  return (
    <WidgetContext.Provider value={{ widgets, toggleWidget }}>
      {children}
    </WidgetContext.Provider>
  );
};

export const useWidgets = () => {
  const context = useContext(WidgetContext);
  if (!context) throw new Error("useWidgets must be used inside WidgetProvider");
  return context;
};
