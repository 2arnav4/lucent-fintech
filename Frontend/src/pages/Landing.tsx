import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Sparkles, TrendingUp, Users, Shield, ArrowRight } from "lucide-react";
import { useNavigate } from "react-router-dom";

const Landing = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: TrendingUp,
      title: "Custom Dashboard",
      description: "Personalize your financial overview with drag-and-drop widgets",
    },
    {
      icon: Sparkles,
      title: "AI Insights",
      description: "Get intelligent recommendations powered by advanced analytics",
    },
    {
      icon: Users,
      title: "Group Finance",
      description: "Manage shared expenses with friends and family seamlessly",
    },
    {
      icon: Shield,
      title: "Bank-Level Security",
      description: "Your financial data is encrypted and protected 24/7",
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/20 via-background to-background" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,_hsl(var(--primary)/0.2),transparent_50%)]" />
        
        <div className="relative max-w-7xl mx-auto px-6 py-24 lg:py-32">
          <div className="text-center space-y-8 animate-fade-in">
            <h1 className="text-5xl lg:text-7xl font-bold tracking-tight">
              <span className="text-foreground">Illuminate Your</span>
              <br />
              <span className="text-transparent bg-clip-text gradient-violet">Finances</span>
            </h1>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Lucent brings clarity to your financial life with AI-powered insights,
              customizable dashboards, and intelligent expense tracking.
            </p>
            <div className="flex items-center justify-center gap-4">
              <Button
                size="lg"
                className="gap-2 glow-violet"
                onClick={() => navigate("/onboarding")}
              >
                Start Dashboard
                <ArrowRight className="w-4 h-4" />
              </Button>
              <Button size="lg" variant="outline">
                Watch Demo
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="max-w-7xl mx-auto px-6 py-24">
        <div className="text-center mb-16">
          <h2 className="text-3xl lg:text-4xl font-bold text-foreground mb-4">
            Everything you need to master your money
          </h2>
          <p className="text-muted-foreground">
            Powerful features designed to give you complete financial clarity
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature, idx) => (
            <Card
              key={feature.title}
              className="p-6 bg-card border-border hover:border-primary/50 hover:glow-violet transition-all duration-300 animate-fade-in cursor-pointer"
              style={{ animationDelay: `${idx * 100}ms` }}
            >
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                <feature.icon className="w-6 h-6 text-primary" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">
                {feature.title}
              </h3>
              <p className="text-sm text-muted-foreground">{feature.description}</p>
            </Card>
          ))}
        </div>
      </div>

      {/* CTA Section */}
      <div className="max-w-7xl mx-auto px-6 py-24">
        <Card className="p-12 bg-gradient-violet text-center">
          <h2 className="text-3xl lg:text-4xl font-bold text-primary-foreground mb-4">
            Ready to take control?
          </h2>
          <p className="text-primary-foreground/80 mb-8 max-w-2xl mx-auto">
            Join thousands of users who have transformed their financial lives with Lucent
          </p>
          <Button
            size="lg"
            variant="secondary"
            className="gap-2"
            onClick={() => navigate("/onboarding")}
          >
            Get Started Free
            <ArrowRight className="w-4 h-4" />
          </Button>
        </Card>
      </div>

      {/* Footer */}
      <footer className="border-t border-border py-12">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="text-2xl font-bold">LUCENT</div>
            <div className="flex gap-8 text-sm text-muted-foreground">
              <a href="#" className="hover:text-foreground transition-colors">Privacy</a>
              <a href="#" className="hover:text-foreground transition-colors">About</a>
              <a href="#" className="hover:text-foreground transition-colors">Contact</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
