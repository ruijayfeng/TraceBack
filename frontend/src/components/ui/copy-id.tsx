import { Check, Copy } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { shortId } from "@/lib/ids";
import { notify } from "@/components/ui/toast";
import { cn } from "@/lib/utils";

async function writeClipboard(text: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  // Fallback for non-secure contexts and older browsers.
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  const ok = document.execCommand?.("copy");
  area.remove();
  if (!ok) throw new Error("copy_failed");
}

export function CopyButton({
  value,
  label = "ID",
  className,
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = useCallback(
    async (event: React.MouseEvent<HTMLButtonElement>) => {
      event.stopPropagation();
      try {
        await writeClipboard(value);
        setState("copied");
        notify.success("完整 ID 已复制");
      } catch {
        setState("failed");
        notify.error("复制失败，请手动选择 ID");
      }
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setState("idle"), 2000);
    },
    [value],
  );

  return (
    <button
      aria-label={state === "copied" ? `已复制${label}` : `复制${label}`}
      className={cn(
        "inline-flex size-6 shrink-0 cursor-pointer items-center justify-center rounded-sm border-0 bg-transparent p-0 text-muted-foreground transition-colors",
        "hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
        state === "copied" && "text-success-foreground",
        state === "failed" && "text-destructive-foreground",
        className,
      )}
      data-copy-state={state}
      onClick={copy}
      title={state === "copied" ? "已复制完整 ID" : state === "failed" ? "复制失败，请手动选择" : "复制完整 ID"}
      type="button"
    >
      {state === "copied" ? (
        <Check aria-hidden size={13} strokeWidth={2.25} />
      ) : (
        <Copy aria-hidden size={13} strokeWidth={1.75} />
      )}
      <span aria-live="polite" className="sr-only" role="status">
        {state === "copied" ? `已复制${label}` : state === "failed" ? "复制失败，请手动选择 ID" : ""}
      </span>
    </button>
  );
}

export function CopyId({
  value,
  label = "ID",
  copy = true,
  className,
}: {
  value: string;
  label?: string;
  copy?: boolean;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex max-w-full items-center gap-1 align-middle", className)}>
      <code className="font-mono text-xs text-foreground" title={value}>
        {shortId(value)}
      </code>
      {copy && <CopyButton label={label} value={value} />}
    </span>
  );
}
