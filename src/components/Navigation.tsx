import { ChevronDown, Mail, Beaker, BookOpen, Search, AlertTriangle } from "lucide-react";
import { useState } from "react";

interface NavigationProps {
  activeSection: string;
  onNavigate: (section: string) => void;
}

export function Navigation({ activeSection, onNavigate }: NavigationProps) {
  const [learnExpanded, setLearnExpanded] = useState(true);

  const navItems = [
    {
      id: "intro",
      label: "Introduction",
      icon: BookOpen,
    },
    {
      id: "learn",
      label: "Learn Email Authentication",
      icon: Mail,
      children: [
        { id: "spf", label: "SPF" },
        { id: "dkim", label: "DKIM" },
        { id: "dmarc", label: "DMARC" },
      ],
    },
    {
      id: "subdomains",
      label: "Using Subdomains",
      icon: BookOpen,
    },
    {
      id: "mistakes",
      label: "Common Mistakes",
      icon: AlertTriangle,
    },
    {
      id: "lookup",
      label: "DNS Lookup Tool",
      icon: Search,
    },
    {
      id: "lab",
      label: "Practice Lab",
      icon: Beaker,
    },
  ];

  const handleClick = (id: string) => {
    if (id === "learn") {
      setLearnExpanded(!learnExpanded);
      if (!learnExpanded) {
        onNavigate("spf");
      }
    } else {
      onNavigate(id);
    }
  };

  const isLearnSection = ["spf", "dkim", "dmarc"].includes(activeSection);

  return (
    <nav className="bg-white/5 backdrop-blur-xl border-r border-white/20 h-full p-6 overflow-y-auto">
      <div className="mb-8">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-blue-500/20 backdrop-blur-xl border border-blue-400/30 rounded-full mb-3">
          <Mail className="h-6 w-6 text-blue-300" />
        </div>
        <h3 className="text-white">Email Deliverability</h3>
        <p className="text-white/60 text-sm mt-1">Email Authentication (SPF, DKIM, DMARC)</p>
      </div>

      <div className="space-y-1">
        {navItems.map((item) => (
          <div key={item.id}>
            <button
              onClick={() => handleClick(item.id)}
              className={`w-full flex items-center justify-between px-4 py-3 rounded-lg transition-colors ${(activeSection === item.id || (item.id === "learn" && isLearnSection))
                  ? "bg-blue-500/20 text-white"
                  : "text-white/70 hover:bg-white/5 hover:text-white"
                }`}
            >
              <div className="flex items-center gap-3">
                {item.icon && <item.icon className="h-5 w-5" />}
                <span>{item.label}</span>
              </div>
              {item.children && (
                <ChevronDown
                  className={`h-4 w-4 transition-transform ${learnExpanded ? "rotate-180" : ""
                    }`}
                />
              )}
            </button>

            {item.children && learnExpanded && (
              <div className="ml-4 mt-1 space-y-1 border-l border-white/10 pl-4">
                {item.children.map((child) => (
                  <button
                    key={child.id}
                    onClick={() => onNavigate(child.id)}
                    className={`w-full text-left px-4 py-2 rounded-lg transition-colors ${activeSection === child.id
                        ? "bg-blue-500/10 text-white"
                        : "text-white/60 hover:bg-white/5 hover:text-white"
                      }`}
                  >
                    {child.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </nav>
  );
}
