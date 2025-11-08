import { useState } from "react";
import { Layout } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Users, Plus, Upload, DollarSign } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const circles = [
  {
    id: 1,
    name: "Roommates",
    members: ["You", "Alex", "Jordan"],
    totalSpent: 1245.50,
    expenses: [
      { merchant: "Rent", date: "Dec 1", amount: 900.00, paidBy: "You" },
      { merchant: "Utilities", date: "Dec 5", amount: 145.50, paidBy: "Alex" },
      { merchant: "Groceries", date: "Dec 10", amount: 200.00, paidBy: "Jordan" },
    ],
  },
  {
    id: 2,
    name: "Trip to NYC",
    members: ["You", "Sam", "Taylor", "Morgan"],
    totalSpent: 2340.75,
    expenses: [
      { merchant: "Hotel", date: "Nov 15", amount: 1200.00, paidBy: "You" },
      { merchant: "Dinner", date: "Nov 16", amount: 340.75, paidBy: "Sam" },
      { merchant: "Museum Tickets", date: "Nov 17", amount: 800.00, paidBy: "Taylor" },
    ],
  },
];

const Circles = () => {
  const { toast } = useToast();
  const [selectedCircle, setSelectedCircle] = useState(circles[0]);
  const [newExpense, setNewExpense] = useState({ merchant: "", amount: "" });

  const handleAddExpense = () => {
    toast({
      title: "Expense Added",
      description: `${newExpense.merchant} - $${newExpense.amount} added successfully`,
    });
    setNewExpense({ merchant: "", amount: "" });
  };

  return (
    <Layout>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-2">Lucent Circles</h1>
          <p className="text-muted-foreground">Manage shared expenses with your groups</p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="w-4 h-4" />
              Create Circle
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-popover border-border">
            <DialogHeader>
              <DialogTitle>Create New Circle</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label>Circle Name</Label>
                <Input placeholder="e.g., Roommates, Trip to Europe" className="bg-input" />
              </div>
              <div>
                <Label>Add Members</Label>
                <Input placeholder="Enter email addresses" className="bg-input" />
              </div>
              <Button className="w-full">Create Circle</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Circle Cards */}
        <div className="space-y-4">
          {circles.map((circle) => (
            <Card
              key={circle.id}
              className={`p-6 cursor-pointer transition-all duration-300 ${
                selectedCircle.id === circle.id
                  ? "border-primary glow-violet"
                  : "border-border hover:border-primary/50"
              }`}
              onClick={() => setSelectedCircle(circle)}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-foreground mb-1">{circle.name}</h3>
                  <p className="text-sm text-muted-foreground">{circle.members.length} members</p>
                </div>
                <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                  <Users className="w-5 h-5 text-primary" />
                </div>
              </div>
              <div className="flex -space-x-2 mb-4">
                {circle.members.slice(0, 3).map((member, idx) => (
                  <div
                    key={idx}
                    className="w-8 h-8 rounded-full bg-gradient-violet border-2 border-background flex items-center justify-center text-xs font-semibold"
                  >
                    {member[0]}
                  </div>
                ))}
              </div>
              <div className="pt-4 border-t border-border">
                <p className="text-xs text-muted-foreground mb-1">Total Spent</p>
                <p className="text-xl font-bold text-foreground">
                  ${circle.totalSpent.toLocaleString()}
                </p>
              </div>
            </Card>
          ))}
        </div>

        {/* Circle Detail View */}
        <div className="lg:col-span-2">
          <Card className="p-6 bg-card border-border">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-foreground">{selectedCircle.name}</h2>
              <Dialog>
                <DialogTrigger asChild>
                  <Button className="gap-2">
                    <Plus className="w-4 h-4" />
                    Add Expense
                  </Button>
                </DialogTrigger>
                <DialogContent className="bg-popover border-border">
                  <DialogHeader>
                    <DialogTitle>Add Expense</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Label>Merchant/Description</Label>
                      <Input
                        placeholder="e.g., Dinner, Groceries"
                        value={newExpense.merchant}
                        onChange={(e) =>
                          setNewExpense({ ...newExpense, merchant: e.target.value })
                        }
                        className="bg-input"
                      />
                    </div>
                    <div>
                      <Label>Amount</Label>
                      <Input
                        type="number"
                        placeholder="0.00"
                        value={newExpense.amount}
                        onChange={(e) =>
                          setNewExpense({ ...newExpense, amount: e.target.value })
                        }
                        className="bg-input"
                      />
                    </div>
                    <div className="border-2 border-dashed border-border rounded-lg p-8 text-center cursor-pointer hover:border-primary/50 transition-colors">
                      <Upload className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                      <p className="text-sm text-muted-foreground">
                        Upload receipt (optional)
                      </p>
                    </div>
                    <div>
                      <Label>Split Method</Label>
                      <div className="grid grid-cols-3 gap-2 mt-2">
                        <Button variant="outline" size="sm">Equal</Button>
                        <Button variant="outline" size="sm">Custom</Button>
                        <Button variant="outline" size="sm" className="gap-1">
                          AI Split
                        </Button>
                      </div>
                    </div>
                    <Button className="w-full" onClick={handleAddExpense}>
                      Add Expense
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </div>

            <div className="mb-6">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-muted-foreground">Fairness Ring</span>
                <span className="text-sm text-success">Balanced</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-violet transition-all duration-500"
                  style={{ width: "85%" }}
                />
              </div>
            </div>

            <div className="space-y-3">
              <h3 className="text-lg font-semibold text-foreground mb-4">Recent Expenses</h3>
              {selectedCircle.expenses.map((expense, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-4 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <DollarSign className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-foreground">{expense.merchant}</p>
                      <p className="text-xs text-muted-foreground">
                        {expense.date} • Paid by {expense.paidBy}
                      </p>
                    </div>
                  </div>
                  <span className="text-sm font-semibold text-foreground">
                    ${expense.amount.toFixed(2)}
                  </span>
                </div>
              ))}
            </div>

            <div className="mt-6 pt-6 border-t border-border">
              <Button className="w-full" variant="outline">
                Settle Up
              </Button>
            </div>
          </Card>
        </div>
      </div>
    </Layout>
  );
};

export default Circles;
