import { useState, useEffect } from "react";
import { Layout } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Users, Plus, IndianRupee } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { API_BASE_URL } from "@/lib/api";

interface Circle {
  id: number;
  name: string;
  owner_id: number;
  members: Array<{
    id: number;
    email: string;
  }>;
  expenses?: Array<{
    id: number;
    amount: number;
    description: string;
    date: string;
    payer_id: number;
  }>;
}

const Circles = () => {
  const { toast } = useToast();
  const [circles, setCircles] = useState<Circle[]>([]);
  const [selectedCircle, setSelectedCircle] = useState<Circle | null>(null);
  const [newCircle, setNewCircle] = useState({ name: "", members: "" });
  const [newExpense, setNewExpense] = useState({ merchant: "", amount: "" });
  const [loading, setLoading] = useState(false);

  // ✅ Helper: Ensure auth & token
  const ensureAuth = async () => {
    const token = localStorage.getItem("token");
    if (!token) {
      try {
        const signupResp = await fetch(`${API_BASE_URL}/signup`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: "test@example.com",
            password: "test123",
          }),
        });

        if (!signupResp.ok && signupResp.status !== 409) {
          throw new Error("Failed to create test account");
        }

        const loginResp = await fetch(`${API_BASE_URL}/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: "test@example.com",
            password: "test123",
          }),
        });

        if (!loginResp.ok) throw new Error("Failed to log in");

        const { token } = await loginResp.json();
        localStorage.setItem("token", token);
        return token;
      } catch {
        toast({
          title: "Authentication Error",
          description: "Failed to authenticate. Please try again.",
          variant: "destructive",
        });
        return null;
      }
    }
    return token;
  };

  // ✅ Fetch Circles with normalization
  const fetchCircles = async () => {
    try {
      const token = await ensureAuth();
      if (!token) return;

      const response = await fetch(`${API_BASE_URL}/circles`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) throw new Error("Failed to fetch circles");

      const data = await response.json();

      // 💪 Normalize data so nothing breaks
      const safeData = data.map((circle: any) => ({
        ...circle,
        members: circle.members || [],
        expenses: circle.expenses || [],
      }));

      setCircles(safeData);
      if (safeData.length > 0) setSelectedCircle(safeData[0]);
    } catch {
      toast({
        title: "Error",
        description: "Failed to load circles",
        variant: "destructive",
      });
    }
  };

  useEffect(() => {
    const initAuth = async () => {
      const token = await ensureAuth();
      if (token) await fetchCircles();
    };
    initAuth();
  }, []);

  // ✅ Create new circle
  const handleCreateCircle = async () => {
    try {
      setLoading(true);
      const token = await ensureAuth();
      if (!token) {
        setLoading(false);
        return;
      }

      const response = await fetch(`${API_BASE_URL}/circles`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: newCircle.name,
          members: newCircle.members
            .split(",")
            .map((email) => email.trim())
            .filter(Boolean),
        }),
      });

      if (!response.ok) throw new Error("Failed to create circle");

      await fetchCircles();
      setNewCircle({ name: "", members: "" });
      toast({ title: "Success", description: "Circle created successfully" });
    } catch {
      toast({
        title: "Error",
        description: "Failed to create circle",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  // ✅ Add expense
  const handleAddExpense = async () => {
    if (!selectedCircle) return;

    try {
      setLoading(true);
      const token = await ensureAuth();
      if (!token) {
        setLoading(false);
        return;
      }

      const response = await fetch(
        `${API_BASE_URL}/circles/${selectedCircle.id}/expenses`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            merchant: newExpense.merchant,
            amount: parseFloat(newExpense.amount),
          }),
        }
      );

      if (!response.ok) throw new Error("Failed to add expense");

      await fetchCircles();
      setNewExpense({ merchant: "", amount: "" });
      toast({ title: "Success", description: "Expense added successfully" });
    } catch {
      toast({
        title: "Error",
        description: "Failed to add expense",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const calculateTotalSpent = (expenses: Circle["expenses"]) =>
    expenses ? expenses.reduce((t, e) => t + e.amount, 0) : 0;

  const formatDate = (dateString: string) =>
    new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    });

  // ✅ UI Rendering
  return (
    <Layout>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-2">
            Lucent Circles
          </h1>
          <p className="text-muted-foreground">
            Manage shared expenses with your groups
          </p>
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
                <Input
                  placeholder="e.g., Roommates, Trip to Europe"
                  value={newCircle.name}
                  onChange={(e) =>
                    setNewCircle({ ...newCircle, name: e.target.value })
                  }
                />
              </div>
              <div>
                <Label>Members (comma-separated emails)</Label>
                <Input
                  placeholder="friend@example.com, another@example.com"
                  value={newCircle.members}
                  onChange={(e) =>
                    setNewCircle({ ...newCircle, members: e.target.value })
                  }
                />
              </div>
              <Button
                onClick={handleCreateCircle}
                disabled={loading || !newCircle.name}
                className="w-full"
              >
                {loading ? "Creating..." : "Create Circle"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Circles List */}
        <div className="space-y-4">
          {circles.map((circle) => (
            <Card
              key={circle.id}
              className={`p-6 cursor-pointer transition-all duration-300 ${
                selectedCircle?.id === circle.id
                  ? "border-primary shadow-[0_0_25px_rgba(139,92,246,0.25)]"
                  : "border-border hover:border-primary/50"
              }`}
              onClick={() => setSelectedCircle(circle)}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-foreground mb-1">
                    {circle.name}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    {circle.members?.length ?? 0} members
                  </p>
                </div>
                <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                  <Users className="w-5 h-5 text-primary" />
                </div>
              </div>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <IndianRupee className="w-4 h-4" />
                Total Spent:{" "}
                {calculateTotalSpent(circle.expenses).toLocaleString("en-IN", {
                  style: "currency",
                  currency: "INR",
                })}
              </div>
            </Card>
          ))}
        </div>

        {/* Selected Circle Details */}
        {selectedCircle && (
          <div className="lg:col-span-2 space-y-6">
            <Card className="p-6 bg-card border-border">
              <div className="flex items-center gap-4 mb-6">
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                  <Users className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-foreground">
                    {selectedCircle.name}
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    {selectedCircle.members?.length ?? 0} members
                  </p>
                </div>
              </div>

              {/* Members */}
              <div className="space-y-2 mb-6">
                <h3 className="text-sm font-medium text-foreground">Members</h3>
                <div className="grid grid-cols-2 gap-2">
                  {selectedCircle.members?.map((member) => (
                    <div
                      key={member.id}
                      className="text-sm text-muted-foreground flex items-center gap-2"
                    >
                      <div className="w-2 h-2 rounded-full bg-primary" />
                      {member.email}
                    </div>
                  ))}
                </div>
              </div>

              {/* Add Expense */}
              <div className="flex gap-2 mb-4">
                <Input
                  placeholder="Merchant name"
                  value={newExpense.merchant}
                  onChange={(e) =>
                    setNewExpense({ ...newExpense, merchant: e.target.value })
                  }
                />
                <Input
                  type="number"
                  placeholder="Amount"
                  value={newExpense.amount}
                  onChange={(e) =>
                    setNewExpense({ ...newExpense, amount: e.target.value })
                  }
                />
                <Button
                  onClick={handleAddExpense}
                  disabled={!newExpense.merchant || !newExpense.amount}
                >
                  Add
                </Button>
              </div>

              {/* Expenses */}
              <div className="space-y-3">
                {selectedCircle.expenses?.length ? (
                  selectedCircle.expenses.map((expense) => (
                    <div
                      key={expense.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-muted/30"
                    >
                      <div>
                        <p className="text-sm font-medium text-foreground">
                          {expense.description}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Paid by member {expense.payer_id} •{" "}
                          {formatDate(expense.date)}
                        </p>
                      </div>
                      <p className="text-sm font-medium text-foreground">
                        {expense.amount.toLocaleString("en-IN", {
                          style: "currency",
                          currency: "INR",
                        })}
                      </p>
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-muted-foreground">
                    No expenses yet.
                  </p>
                )}
              </div>
            </Card>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default Circles;
