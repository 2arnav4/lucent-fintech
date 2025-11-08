"use client";
import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";

interface CreateCircleDialogProps {
  open: boolean;
  onClose: () => void;
}

export const CreateCircleDialog = ({ open, onClose }: CreateCircleDialogProps) => {
  const [circleName, setCircleName] = useState("");
  const [members, setMembers] = useState("");
  const { toast } = useToast();

  const handleCreate = () => {
    toast({
      title: "Circle Created 🎉",
      description: `${circleName} has been successfully created.`,
    });
    setCircleName("");
    setMembers("");
    onClose();
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
            <Label>Add Members</Label>
            <Input
              placeholder="Enter email addresses"
              value={members}
              onChange={(e) => setMembers(e.target.value)}
              className="bg-input"
            />
          </div>
          <Button className="w-full" onClick={handleCreate}>
            Create Circle
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};
