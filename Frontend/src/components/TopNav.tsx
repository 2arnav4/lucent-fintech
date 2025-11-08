import { useState } from "react";
import { Plus, Bell } from "lucide-react";
import { Button } from "./ui/button";
import { useNavigate } from "react-router-dom";
import { CreateCircleDialog } from "@/components/CreateCircleDialog"; // ✅ imported

export const TopNav = () => {
  const navigate = useNavigate();
  const [openModal, setOpenModal] = useState(false);

  return (
    <>
      <header className="h-16 border-b border-border flex items-center justify-end px-6 lg:px-8 bg-card/50 backdrop-blur-sm">
        <div className="flex items-center gap-4">
          {/* ➕ Create Circle Popup */}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setOpenModal(true)} // ✅ open modal directly
          >
            <Plus className="w-5 h-5" />
          </Button>

          {/* 🔔 News */}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate("/news")}
          >
            <Bell className="w-5 h-5" />
          </Button>

          {/* 🧑‍💼 Profile */}
          <div
            onClick={() => navigate("/settings")}
            className="w-8 h-8 rounded-full bg-gradient-violet flex items-center justify-center text-sm font-semibold cursor-pointer hover:opacity-90 transition"
          >
            IR
          </div>
        </div>
      </header>

      {/* ✅ Global Create Circle Modal */}
      <CreateCircleDialog open={openModal} onClose={() => setOpenModal(false)} />
    </>
  );
};
