"use client";
import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { API_BASE_URL } from "@/lib/api";

interface CreateCircleDialogProps {
  open: boolean;
  onClose: () => void;
}

export const CreateCircleDialog = ({ open, onClose }: CreateCircleDialogProps) => {
  const [circleName, setCircleName] = useState("");
  const [members, setMembers] = useState("");
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const handleCreate = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        throw new Error("Please log in first");
      }

      const response = await fetch(`${API_BASE_URL}/circles`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: circleName,
          members: members
            .split(",")
            .map((email) => email.trim())
            .filter(Boolean),
        }),
      });

      if (!response.ok) throw new Error("Failed to create circle");

      toast({
        title: "Circle Created 🎉",
        description: `${circleName} has been successfully created.`,
      });
      setCircleName("");
      setMembers("");
      onClose();
      // If we are on the circles page, we can trigger a page reload to show the new circle
      if (window.location.pathname === "/circles") {
        window.location.reload();
      }
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to create circle",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="bg-popover border-border">
        <DialogHeader>
          <DialogTitle>Create New Circle</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Circle Name</Label>
            <Input
              placeholder="e.g., Roommates, Goa Trip"
              value={circleName}
              onChange={(e) => setCircleName(e.target.value)}
              className="bg-input"
            />
          </div>
          <div>
            <Label>Add Members (comma-separated emails)</Label>
            <Input
              placeholder="friend@example.com, another@example.com"
              value={members}
              onChange={(e) => setMembers(e.target.value)}
              className="bg-input"
            />
          </div>
          <Button className="w-full" onClick={handleCreate} disabled={loading || !circleName}>
            {loading ? "Creating..." : "Create Circle"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};
