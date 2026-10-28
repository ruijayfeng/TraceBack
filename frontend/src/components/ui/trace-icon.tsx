import type { LucideIcon, LucideProps } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * One wrapper for every functional icon: consistent optical size/stroke and
 * decorative by default. Pass `label` only when the icon carries meaning that
 * is not already present in adjacent text.
 */
export function TraceIcon({
  icon: Icon,
  label,
  className,
  size = 16,
  strokeWidth = 1.75,
  ...props
}: LucideProps & { icon: LucideIcon; label?: string }) {
  return (
    <Icon
      aria-hidden={label ? undefined : true}
      aria-label={label}
      className={cn("shrink-0", className)}
      focusable="false"
      role={label ? "img" : undefined}
      size={size}
      strokeWidth={strokeWidth}
      {...props}
    />
  );
}
