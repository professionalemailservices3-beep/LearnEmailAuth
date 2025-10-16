import { Card } from "./ui/card";
import { Alert, AlertDescription } from "./ui/alert";
import { AlertTriangle, Info } from "lucide-react";

interface CourseSectionProps {
  title: string;
  description: string;
  children: React.ReactNode;
}

export function CourseSection({ title, description, children }: CourseSectionProps) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-white mb-2">{title}</h2>
        <p className="text-white/70">{description}</p>
      </div>
      {children}
    </div>
  );
}

interface ContentCardProps {
  title?: string;
  children: React.ReactNode;
}

export function ContentCard({ title, children }: ContentCardProps) {
  return (
    <Card className="bg-white/10 backdrop-blur-xl border-white/20 p-6">
      {title && <h3 className="text-white mb-4">{title}</h3>}
      <div className="text-white/80 space-y-4">
        {children}
      </div>
    </Card>
  );
}

interface MistakeAlertProps {
  type?: "warning" | "info";
  title: string;
  children: React.ReactNode;
}

export function MistakeAlert({ type = "warning", title, children }: MistakeAlertProps) {
  const Icon = type === "warning" ? AlertTriangle : Info;
  const bgColor = type === "warning" ? "bg-amber-500/20" : "bg-blue-500/10";
  const borderColor = type === "warning" ? "border-amber-500/50" : "border-blue-500/30";
  const iconColor = type === "warning" ? "text-amber-300" : "text-blue-400";
  const titleColor = type === "warning" ? "text-amber-200" : "text-blue-300";
  
  return (
    <Alert className={`${bgColor} backdrop-blur-xl ${borderColor} border-2`}>
      <Icon className={`h-6 w-6 ${iconColor}`} />
      <AlertDescription className="text-white/90">
        <span className={`block mb-3 ${titleColor}`}>{title}</span>
        {children}
      </AlertDescription>
    </Alert>
  );
}

interface CodeBlockProps {
  children: React.ReactNode;
  inline?: boolean;
}

export function CodeBlock({ children, inline = false }: CodeBlockProps) {
  if (inline) {
    return (
      <code className="bg-white/20 px-2 py-1 rounded text-blue-200 text-sm">
        {children}
      </code>
    );
  }
  
  return (
    <pre className="bg-black/30 backdrop-blur-sm p-4 rounded-lg overflow-x-auto border border-white/10">
      <code className="text-blue-200 text-sm">{children}</code>
    </pre>
  );
}
