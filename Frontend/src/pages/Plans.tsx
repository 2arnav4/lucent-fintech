import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

const plans = [
  {
    name: "Free",
    price: { month: 0, half: 0, year: 0 },
    description: "Get started with essential money tracking tools",
    features: [
      "Basic financial dashboard",
      "Manual expense tracking",
      "2 Circles for group splits",
      "Limited widgets (Net Worth, Budget)",
      "Email support"
    ]
  },
  {
    name: "Pro",
    price: { month: 199, half: 999, year: 1799 },
    description: "Perfect for young professionals",
    features: [
      "AI-powered insights",
      "Automatic expense categorization",
      "FIRE number tracker",
      "Up to 10 Circles",
      "Priority email support"
    ],
    popular: true
  },
  {
    name: "Prime",
    price: { month: 499, half: 2499, year: 4499 },
    description: "For investors and serious savers",
    features: [
      "Everything in Pro",
      "Stock + Crypto integration",
      "OCR bill scanning (WhatsApp ready)",
      "AI portfolio suggestions",
      "Custom reports and analytics",
      "Unlimited Circles"
    ]
  },
  {
    name: "Enterprise",
    price: { month: 999, half: 5499, year: 9999 },
    description: "For teams and organizations",
    features: [
      "Everything in Prime",
      "Team dashboards",
      "UPI + custom integrations",
      "Dedicated account manager",
      "24/7 support"
    ]
  }
];

export default function Plans() {
  const [billing, setBilling] = useState<"month" | "half" | "year">("month");

  const billingLabels = {
    month: "Monthly",
    half: "6 Months",
    year: "Yearly"
  };

  return (
    <div className="container mx-auto py-16 px-4">
      {/* Header */}
      <div className="text-center mb-10">
        <h1 className="text-4xl font-bold mb-2">Choose Your Lucent Plan</h1>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          Take control of your finances. Simple plans designed for India’s financial journey.
        </p>
      </div>

      {/* Billing Toggle */}
      <div className="flex justify-center mb-10">
        <div className="bg-muted rounded-full p-1 flex">
          {Object.entries(billingLabels).map(([key, label]) => (
            <Button
              key={key}
              onClick={() => setBilling(key as "month" | "half" | "year")}
              variant={billing === key ? "default" : "ghost"}
              className="rounded-full px-5 py-2 text-sm"
            >
              {label}
            </Button>
          ))}
        </div>
      </div>

      {/* Pricing Cards */}
      <div className="grid md:grid-cols-4 gap-8 max-w-7xl mx-auto">
        {plans.map((plan) => (
          <Card
            key={plan.name}
            className={`relative p-6 transition-all hover:shadow-lg hover:scale-[1.02] ${
              plan.popular ? "border-primary ring-2 ring-primary/60" : ""
            }`}
          >
            {plan.popular && (
              <div className="absolute -top-3 right-4 px-3 py-1 bg-primary text-primary-foreground text-xs font-medium rounded-full">
                Most Popular
              </div>
            )}

            <div className="text-center mb-6">
              <h3 className="text-2xl font-semibold mb-2">{plan.name}</h3>
              <div className="mb-2 flex items-baseline justify-center gap-1">
                <span className="text-4xl font-bold">
                  {plan.price[billing] === 0 ? "Free" : `₹${plan.price[billing]}`}
                </span>
                {plan.price[billing] !== 0 && (
                  <span className="text-muted-foreground text-sm">/{billingLabels[billing]}</span>
                )}
              </div>
              <p className="text-muted-foreground text-sm">{plan.description}</p>
            </div>

            <div className="space-y-3 mb-6">
              {plan.features.map((feature) => (
                <div key={feature} className="flex items-start gap-2">
                  <svg
                    className="w-4 h-4 mt-1 text-primary flex-shrink-0"
                    fill="none"
                    strokeWidth="2.5"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                  <span className="text-sm text-foreground">{feature}</span>
                </div>
              ))}
            </div>

            <Button className="w-full" variant={plan.popular ? "default" : "outline"}>
              {plan.price[billing] === 0 ? "Get Started Free" : "Upgrade Now"}
            </Button>
          </Card>
        ))}
      </div>
    </div>
  );
}
