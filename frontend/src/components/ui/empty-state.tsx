import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * One empty-state shape: what is empty, why it can be empty, and the next
 * action. Left-aligned like the rest of the work surface, not a centred banner.
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
    <div className={cn("empty-state", className)}>
      <h3>{title}</h3>
      {description && <p>{description}</p>}
      {action && <div className="mt-1 flex flex-wrap items-center gap-2">{action}</div>}
    </div>
  );
}
