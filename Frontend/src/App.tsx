import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

// Pages
import Landing from "./pages/Landing";
import Onboarding from "./pages/Onboarding";
import Dashboard from "./pages/Dashboard";
import Circles from "./pages/Circles";
import Analytics from "./pages/Analytics";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";
import Plans from "./pages/Plans";
import News from "./pages/News";
import Widgets from "./pages/Widgets"; // ✅ Widget Manager

// Context
import { WidgetProvider } from "@/context/WidgetContext"; // ✅ Global Context

// Create query client for Tanstack React Query
const queryClient = new QueryClient();

const App = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WidgetProvider> {/* ✅ Wraps everything to provide global widget state */}
          <BrowserRouter>
            <Routes>
              <Route path="/" element={<Landing />} />
              <Route path="/onboarding" element={<Onboarding />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/circles" element={<Circles />} />
              <Route path="/analytics" element={<Analytics />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/plans" element={<Plans />} />
              <Route path="/news" element={<News />} />
              <Route path="/widgets" element={<Widgets />} /> {/* ✅ Widget Manager route */}
              
              {/* Redirects for unused paths */}
              <Route path="/inbox" element={<Navigate to="/dashboard" replace />} />
              <Route path="/reports" element={<Navigate to="/analytics" replace />} />
              <Route path="/trends" element={<Navigate to="/analytics" replace />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </BrowserRouter>

          {/* ✅ Keep global toasters *outside* router for consistent access */}
          <Toaster />
          <Sonner />
        </WidgetProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
