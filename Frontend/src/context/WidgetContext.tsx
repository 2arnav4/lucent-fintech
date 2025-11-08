// src/context/WidgetContext.tsx
import React, { createContext, useContext, useEffect, useState } from "react";

export type WidgetKeys =
  | "netWorth"
  | "recentTransactions"
  | "monthlyBudget"
  | "savingsGoals"
  | "aiInsights"
  | "income"
  | "expenditure"
  | "investments"
  | "savings"
  | "monthlyWeeklyYearly"
  | "financialGoals"
  | "creditScore"
  | "lucentCircle";

export type WidgetsState = Record<WidgetKeys, boolean>;

const DEFAULT_STATE: WidgetsState = {
  netWorth: true,
  recentTransactions: true,
  monthlyBudget: true,
  savingsGoals: true,
  aiInsights: true,
  income: false,
  expenditure: false,
  investments: false,
  savings: false,
  monthlyWeeklyYearly: false,
  financialGoals: true,
  creditScore: false,
  lucentCircle: true,
};

type WidgetContextType = {
  widgets: WidgetsState;
  toggleWidget: (id: WidgetKeys, value?: boolean) => void;
  setWidgets: (s: WidgetsState) => void;
};

const WidgetContext = createContext<WidgetContextType | undefined>(undefined);

export const WidgetProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [widgets, setWidgetsState] = useState<WidgetsState>(() => {
    try {
      const raw = localStorage.getItem("lucent_widgets");
      if (raw) return JSON.parse(raw) as WidgetsState;
    } catch (e) {
      /* ignore */
    }
    return DEFAULT_STATE;
  });

  useEffect(() => {
    try {
      localStorage.setItem("lucent_widgets", JSON.stringify(widgets));
    } catch (e) {
      // ignore
    }
  }, [widgets]);

  const toggleWidget = (id: WidgetKeys, value?: boolean) => {
    setWidgetsState((prev) => {
      const next = { ...prev, [id]: typeof value === "boolean" ? value : !prev[id] };
      return next;
    });
  };

  const setWidgets = (s: WidgetsState) => setWidgetsState(s);

  return (
    <WidgetContext.Provider value={{ widgets, toggleWidget, setWidgets }}>
      {children}
    </WidgetContext.Provider>
  );
};

export const useWidgets = () => {
  const ctx = useContext(WidgetContext);
  if (!ctx) throw new Error("useWidgets must be used inside WidgetProvider");
  return ctx;
};
