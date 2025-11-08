import { useState } from "react";
import { Card } from "@/components/ui/card";
import { WidgetActions } from "@/components/widgets/WidgetActions";

export const NetWorthWidget = () => {
  const [loading, setLoading] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [title, setTitle] = useState("Net Worth");

  if (hidden) return null;

  const handleRefresh = () => {
    setLoading(true);
    setTimeout(() => setLoading(false), 1500); // simulate data refresh
  };

  const handleEdit = () => {
    const newTitle = prompt("Enter new widget name:", title);
    if (newTitle) setTitle(newTitle);
  };

  const handleRemove = () => setHidden(true);

  return (
    <Card className="p-6 relative">
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
        <p className="text-sm text-muted-foreground animate-pulse">Refreshing data...</p>
      ) : (
        <p className="text-3xl font-bold text-primary">₹1,42,847.32</p>
      )}
    </Card>
  );
};
