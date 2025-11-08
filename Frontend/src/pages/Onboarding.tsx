import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Wallet, TrendingUp, Bitcoin, Users, PieChart, ArrowRight, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";

const interests = [
  { id: "banking", label: "Banking", icon: Wallet },
  { id: "budgeting", label: "Budgeting", icon: PieChart },
  { id: "investing", label: "Investing", icon: TrendingUp },
  { id: "crypto", label: "Crypto", icon: Bitcoin },
  { id: "group", label: "Group Finance", icon: Users },
];

const Onboarding = () => {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [selectedInterests, setSelectedInterests] = useState<string[]>([]);

  const toggleInterest = (id: string) => {
    setSelectedInterests((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const handleComplete = () => {
    navigate("/dashboard");
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-6">
      <div className="w-full max-w-4xl">
        {step === 1 && (
          <div className="text-center space-y-8 animate-fade-in">
            <div className="space-y-4">
              <div className="w-20 h-20 mx-auto rounded-full gradient-violet flex items-center justify-center animate-glow-pulse">
                <span className="text-4xl font-bold text-primary-foreground">L</span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-bold text-foreground">
                Welcome to Lucent
              </h1>
              <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
                Let's personalize your dashboard to match your financial goals
              </p>
            </div>
            <Button size="lg" className="gap-2" onClick={() => setStep(2)}>
              Let's Get Started
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-8 animate-fade-in">
            <div className="text-center">
              <h2 className="text-3xl font-bold text-foreground mb-2">
                What interests you?
              </h2>
              <p className="text-muted-foreground">
                Select all that apply - we'll customize your dashboard accordingly
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {interests.map((interest) => {
                const isSelected = selectedInterests.includes(interest.id);
                return (
                  <Card
                    key={interest.id}
                    className={`p-6 cursor-pointer transition-all duration-300 ${
                      isSelected
                        ? "border-primary bg-primary/5 glow-violet"
                        : "border-border hover:border-primary/50"
                    }`}
                    onClick={() => toggleInterest(interest.id)}
                  >
                    <div className="flex flex-col items-center text-center space-y-3">
                      <div
                        className={`w-16 h-16 rounded-full flex items-center justify-center ${
                          isSelected ? "bg-primary" : "bg-muted"
                        }`}
                      >
                        <interest.icon
                          className={`w-8 h-8 ${
                            isSelected ? "text-primary-foreground" : "text-foreground"
                          }`}
                        />
                      </div>
                      <span className="font-medium text-foreground">{interest.label}</span>
                      <Checkbox checked={isSelected} className="pointer-events-none" />
                    </div>
                  </Card>
                );
              })}
            </div>

            <div className="flex items-center justify-between">
              <Button variant="outline" onClick={() => setStep(1)}>
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back
              </Button>
              <Button onClick={() => setStep(3)} disabled={selectedInterests.length === 0}>
                Continue
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-8 animate-fade-in">
            <div className="text-center">
              <h2 className="text-3xl font-bold text-foreground mb-2">
                Your Dashboard Preview
              </h2>
              <p className="text-muted-foreground">
                Here's what your personalized dashboard will look like
              </p>
            </div>

            <Card className="p-8 bg-card border-border">
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                {selectedInterests.map((id) => {
                  const interest = interests.find((i) => i.id === id);
                  if (!interest) return null;
                  return (
                    <div
                      key={id}
                      className="aspect-square rounded-lg bg-muted/50 flex items-center justify-center border border-border"
                    >
                      <interest.icon className="w-8 h-8 text-primary" />
                    </div>
                  );
                })}
              </div>
            </Card>

            <div className="flex items-center justify-between">
              <Button variant="outline" onClick={() => setStep(2)}>
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back
              </Button>
              <Button onClick={handleComplete} className="gap-2 glow-violet">
                Complete Setup
                <ArrowRight className="w-4 h-4" />
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Onboarding;
