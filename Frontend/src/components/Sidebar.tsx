import { NavLink } from "@/components/NavLink";

import {
  LayoutDashboard,
  FileText,
  TrendingUp,
  Users,
  Settings,
  CreditCard,
  LineChart,
  Newspaper,
  SlidersHorizontal,
} from "lucide-react";

const navItems = [
  { title: "Dashboard", icon: LayoutDashboard, url: "/dashboard" },
  { title: "Widgets", icon: SlidersHorizontal, url: "/widgets" },
  { title: "Trends", icon: LineChart, url: "/trends" },
  // { title: "Portfolio", icon: FileText, url: "/portfolio" },
  { title: "Circles", icon: Users, url: "/circles" },
  { title: "Plans", icon: CreditCard, url: "/plans" },
  { title: "News", icon: Newspaper, url: "/news" },
  { title: "Settings", icon: Settings, url: "/settings" },
];

export const Sidebar = () => {
  return (
    <aside className="w-64 bg-sidebar border-r border-sidebar-border flex flex-col">
      <div className="p-6">
        <h1 className="text-2xl font-bold tracking-wider text-foreground">
          LUCENT
        </h1>
      </div>

      <nav className="flex-1 px-3 space-y-2">
        {navItems.map((item) => (
          <NavLink
            key={item.url}
            to={item.url}
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-muted-foreground hover:text-foreground hover:bg-sidebar-accent transition-all duration-200"
            activeClassName="bg-sidebar-accent text-foreground font-medium"
          >
            <item.icon className="w-4 h-4" />
            <span>{item.title}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-sidebar-border">
        <NavLink
          to="/settings"
          className="flex items-center gap-3 p-3 rounded-lg hover:bg-sidebar-accent transition-all duration-200"
        >
          <div className="w-10 h-10 rounded-full bg-gradient-violet flex items-center justify-center text-sm font-semibold">
            IR
          </div>
          <div className="flex-1">
            <p className="text-sm font-medium text-foreground">Irvin</p>
            <p className="text-xs text-muted-foreground">Founder</p>
          </div>
        </NavLink>
      </div>
    </aside>
  );
};
