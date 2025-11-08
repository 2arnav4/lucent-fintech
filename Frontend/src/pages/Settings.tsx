import { useState } from "react";
import { Layout } from "@/components/Layout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { useToast } from "@/hooks/use-toast";

const Settings = () => {
  const { toast } = useToast();
  const [aiPrivacy, setAiPrivacy] = useState(true);
  const [themeIntensity, setThemeIntensity] = useState([70]);

  const integrations = [
    { name: "Bank of America", status: "connected", type: "Bank" },
    { name: "Coinbase", status: "disconnected", type: "Crypto" },
    { name: "Robinhood", status: "connected", type: "Investments" },
  ];

  const handleSave = () => {
    toast({
      title: "Settings Saved",
      description: "Your preferences have been updated successfully",
    });
  };

  return (
    <Layout>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-foreground mb-2">Settings</h1>
        <p className="text-muted-foreground">Manage your account and preferences</p>
      </div>

      <div className="space-y-6 max-w-4xl">
        <Card className="p-6 bg-card border-border">
          <h2 className="text-xl font-semibold text-foreground mb-4">Profile</h2>
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div className="w-20 h-20 rounded-full bg-gradient-violet flex items-center justify-center text-2xl font-bold">
                IR
              </div>
              <div className="flex-1">
                <Label>Profile Picture</Label>
                <Button variant="outline" size="sm" className="mt-2">
                  Change Photo
                </Button>
              </div>
            </div>
            <div>
              <Label htmlFor="name">Full Name</Label>
              <Input id="name" defaultValue="Irvin" className="mt-2 bg-input" />
            </div>
            <div>
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" defaultValue="irvin@lucent.app" className="mt-2 bg-input" />
            </div>
          </div>
        </Card>

        <Card className="p-6 bg-card border-border">
          <h2 className="text-xl font-semibold text-foreground mb-4">Appearance</h2>
          <div className="space-y-6">
            <div>
              <Label htmlFor="intensity">Violet Intensity</Label>
              <div className="flex items-center gap-4 mt-2">
                <Slider
                  id="intensity"
                  value={themeIntensity}
                  onValueChange={setThemeIntensity}
                  max={100}
                  step={1}
                  className="flex-1"
                />
                <span className="text-sm text-muted-foreground w-12">{themeIntensity[0]}%</span>
              </div>
            </div>
          </div>
        </Card>

        <Card className="p-6 bg-card border-border">
          <h2 className="text-xl font-semibold text-foreground mb-4">Integrations</h2>
          <div className="space-y-3">
            {integrations.map((integration) => (
              <div
                key={integration.name}
                className="flex items-center justify-between p-4 rounded-lg bg-muted/30"
              >
                <div>
                  <p className="text-sm font-medium text-foreground">{integration.name}</p>
                  <p className="text-xs text-muted-foreground">{integration.type}</p>
                </div>
                <Button
                  variant={integration.status === "connected" ? "outline" : "default"}
                  size="sm"
                >
                  {integration.status === "connected" ? "Disconnect" : "Connect"}
                </Button>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-6 bg-card border-border">
          <h2 className="text-xl font-semibold text-foreground mb-4">Privacy</h2>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-foreground">AI Data Usage</p>
              <p className="text-xs text-muted-foreground">
                Allow Lucent to use anonymized data for AI insights
              </p>
            </div>
            <Switch checked={aiPrivacy} onCheckedChange={setAiPrivacy} />
          </div>
        </Card>

        <div className="flex justify-end gap-4">
          <Button variant="outline">Cancel</Button>
          <Button onClick={handleSave}>Save Changes</Button>
        </div>
      </div>
    </Layout>
  );
};

export default Settings;
