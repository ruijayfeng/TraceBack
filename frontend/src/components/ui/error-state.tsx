import { RotateCcw } from "lucide-react";
import { describeError } from "@/lib/errors";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { TraceIcon } from "@/components/ui/trace-icon";

/**
 * Error surface shared by every resource: what failed, the raw code, and a
 * retry action. `role="alert"` is intentional: errors are announced.
 */
export function ErrorState({
  error,
  onRetry,
  scope,
  className,
}: {
  error: string;
  onRetry?: () => void;
  scope?: string;
  className?: string;
}) {
  const described = describeError(error);
  return (
    <div className={cn("notice error", className)} role="alert">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <strong className="text-sm text-destructive-foreground">{described.title}</strong>
        <code className="rounded-sm bg-white/60 px-1.5 py-0.5 font-mono text-2xs text-destructive-foreground">
          {described.code}
        </code>
        {scope && <span className="text-2xs text-muted-foreground">{scope}</span>}
      </div>
      <p className="mt-1 mb-0 text-sm">{described.message}</p>
      {onRetry && described.retryable && (
        <Button
          className="mt-2"
          onClick={onRetry}
          size="xs"
          type="button"
          variant="outline"
        >
          <TraceIcon icon={RotateCcw} size={13} />
          重试
        </Button>
      )}
    </div>
  );
}
