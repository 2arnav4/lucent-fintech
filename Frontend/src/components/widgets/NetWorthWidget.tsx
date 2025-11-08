import { useState } from "react";
import { Card } from "@/components/ui/card";
import { WidgetActions } from "@/components/widgets/WidgetActions";

export const NetWorthWidget = () => {
  const [loading, setLoading] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [title, setTitle] = useState("Net Worth");

  // Sample amount to simulate data
  const [netWorth, setNetWorth] = useState(142847.32);

  if (hidden) return null;

  // Format amount for Indian currency style
  const formattedNetWorth = netWorth.toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    minimumFractionDigits: 2,
  });

  const handleRefresh = () => {
    setLoading(true);
    setTimeout(() => {
      // Simulate new random net worth (like data update)
      const randomChange = Math.floor(Math.random() * 20000) - 10000;
      setNetWorth((prev) => Math.max(0, prev + randomChange));
      setLoading(false);
    }, 1500);
  };

  const handleEdit = () => {
    const newTitle = prompt("Enter new widget name:", title);
    if (newTitle) setTitle(newTitle);
  };

  const handleRemove = () => setHidden(true);

  return (
    <Card
      className="
        p-6 relative 
        transition-all duration-300 
        hover:scale-[1.01] 
        hover:shadow-[0_0_35px_rgba(167,139,250,0.35)]
        bg-card border border-border
      "
    >
      {/* Dropdown menu (top-right corner) */}
      <div className="absolute top-4 right-4">
        <WidgetActions
          onEdit={handleEdit}
          onRefresh={handleRefresh}
          onRemove={handleRemove}
        />
      </div>

      {/* Widget content */}
      <h2 className="text-lg font-semibold mb-2">{title}</h2>

      {loading ? (
        <p className="text-sm text-muted-foreground animate-pulse">
          Refreshing data...
        </p>
      ) : (
        <p className="text-4xl font-bold text-primary tracking-tight">
          {formattedNetWorth}
        </p>
      )}

      <p className="text-sm text-muted-foreground mt-2">
        Total assets minus liabilities as of today
      </p>
    </Card>
  );
};
