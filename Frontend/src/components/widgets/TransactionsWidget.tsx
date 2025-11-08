import { useState } from "react";
import { ShoppingCart, Coffee, Zap, Tv, ArrowDownLeft, ArrowUpRight } from "lucide-react";
import { Card } from "../ui/card";
import { Button } from "../ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "../ui/dialog";
import { ScrollArea } from "../ui/scroll-area";

const transactions = [
  { name: "Whole Foods Market", time: "Today, 2:34 PM", amount: -87.42, icon: ShoppingCart, type: "debit" },
  { name: "Starbucks", time: "Today, 9:15 AM", amount: -6.50, icon: Coffee, type: "debit" },
  { name: "Salary Deposit", time: "Yesterday, 12:00 AM", amount: 8500.00, icon: ArrowDownLeft, type: "credit" },
  { name: "Electric Bill", time: "Dec 15", amount: -142.00, icon: Zap, type: "debit" },
  { name: "Netflix Subscription", time: "Dec 14", amount: -15.99, icon: Tv, type: "debit" },
];

export const TransactionsWidget = () => {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <Card
      className={`p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 ${
        isHovered ? "glow-violet" : ""
      }`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-2">
          <ArrowUpRight className="w-5 h-5 text-primary" />
          <h3 className="text-sm font-medium text-foreground">Recent Transactions</h3>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button variant="link" size="sm" className="text-primary">
              View all
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-popover border-border max-w-2xl">
            <DialogHeader>
              <DialogTitle>All Transactions</DialogTitle>
            </DialogHeader>
            <ScrollArea className="h-96">
              <div className="space-y-3">
                {[...transactions, ...transactions].map((transaction, idx) => (
                  <div key={idx} className="flex items-center justify-between p-3 rounded-lg hover:bg-muted/50">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
                        <transaction.icon className="w-5 h-5 text-foreground" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-foreground">{transaction.name}</p>
                        <p className="text-xs text-muted-foreground">{transaction.time}</p>
                      </div>
                    </div>
                    <span
                      className={`text-sm font-medium ${
                        transaction.type === "credit" ? "text-success" : "text-foreground"
                      }`}
                    >
                      {transaction.amount > 0 ? "+" : ""}${Math.abs(transaction.amount).toFixed(2)}
                    </span>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </DialogContent>
        </Dialog>
      </div>

      <div className="space-y-3">
        {transactions.slice(0, 5).map((transaction, idx) => (
          <div key={idx} className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-muted flex items-center justify-center">
                <transaction.icon className="w-4 h-4 text-foreground" />
              </div>
              <div>
                <p className="text-sm font-medium text-foreground">{transaction.name}</p>
                <p className="text-xs text-muted-foreground">{transaction.time}</p>
              </div>
            </div>
            <span
              className={`text-sm font-medium ${
                transaction.type === "credit" ? "text-success" : "text-foreground"
              }`}
            >
              {transaction.amount > 0 ? "+" : ""}${Math.abs(transaction.amount).toFixed(2)}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
};
