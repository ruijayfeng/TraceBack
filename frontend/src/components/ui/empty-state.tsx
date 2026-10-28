import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * One empty-state shape: what is empty, why it can be empty, and the next
 * action. Copy keeps "未提供" for missing fields and "无" for truly empty sets.
 */
export function EmptyState({
  title,
  description,
  action,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "empty-state flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-muted/40 px-5 py-8 text-center",
        className,
      )}
    >
      <strong className="text-sm font-semibold text-foreground">{title}</strong>
      {description && <p className="m-0 max-w-prose text-sm text-muted-foreground">{description}</p>}
      {action && <div className="mt-1 flex flex-wrap items-center justify-center gap-2">{action}</div>}
    </div>
  );
}
