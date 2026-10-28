// coss.com/ui (Cal.com Design System) - https://github.com/cosscom/ui
// Source: apps/ui/registry/default/ui/sheet.tsx (registry path; declared MIT in the repository)
// Copyright (c) coss.com. See THIRD_PARTY_NOTICES.md and coss-ui.LICENSE in this directory.
// TraceBack adaptation: @base-ui/react 1.9.0 (latest published) has no Dialog.Viewport, so the
// viewport framing lives on the Popup and the coss ScrollArea dependency is replaced by the
// popup's own overflow. Focus trap, Esc, scroll lock and focus restore remain Base UI Dialog.
import { Dialog as SheetPrimitive } from "@base-ui/react/dialog";
import { XIcon } from "lucide-react";
import type React from "react";
import { cn } from "@/lib/utils";

export const Sheet: typeof SheetPrimitive.Root = SheetPrimitive.Root;
export const SheetPortal: typeof SheetPrimitive.Portal = SheetPrimitive.Portal;
export const SheetClose: typeof SheetPrimitive.Close = SheetPrimitive.Close;

export function SheetTrigger(props: SheetPrimitive.Trigger.Props): React.ReactElement {
  return <SheetPrimitive.Trigger data-slot="sheet-trigger" {...props} />;
}

export function SheetBackdrop({ className, ...props }: SheetPrimitive.Backdrop.Props): React.ReactElement {
  return (
    <SheetPrimitive.Backdrop
      className={cn(
        "fixed inset-0 z-50 bg-black/32 transition-all duration-200 data-ending-style:opacity-0 data-starting-style:opacity-0 supports-[-webkit-touch-callout:none]:absolute",
        className,
      )}
      data-slot="sheet-backdrop"
      {...props}
    />
  );
}

export function SheetPopup({
  className,
  children,
  showCloseButton = true,
  side = "right",
  closeProps,
  ...props
}: SheetPrimitive.Popup.Props & {
  showCloseButton?: boolean;
  side?: "right" | "left" | "top" | "bottom";
  closeProps?: SheetPrimitive.Close.Props;
}): React.ReactElement {
  return (
    <SheetPortal>
      <SheetBackdrop />
      <SheetPrimitive.Popup
        className={cn(
          "fixed z-50 flex min-h-0 w-full flex-col overflow-y-auto overscroll-contain border-border bg-popover text-popover-foreground shadow-lg/5 outline-none transition-[opacity,translate] duration-200 ease-in-out will-change-transform",
          "data-ending-style:opacity-0 data-starting-style:opacity-0",
          side === "right" && "inset-y-0 end-0 max-w-md border-s data-ending-style:translate-x-8 data-starting-style:translate-x-8 sm:w-[calc(100%-3rem)] sm:max-w-[580px]",
          side === "left" && "inset-y-0 start-0 max-w-md border-e data-ending-style:-translate-x-8 data-starting-style:-translate-x-8",
          side === "top" && "inset-x-0 top-0 max-h-[85dvh] border-b data-ending-style:-translate-y-8 data-starting-style:-translate-y-8",
          side === "bottom" && "inset-x-0 bottom-0 max-h-[85dvh] rounded-t-2xl border-t data-ending-style:translate-y-8 data-starting-style:translate-y-8",
          // On phones every sheet becomes a bottom sheet for reachability.
          "max-sm:inset-x-0 max-sm:top-auto max-sm:bottom-0 max-sm:max-h-[85dvh] max-sm:max-w-none max-sm:rounded-t-2xl max-sm:border-t max-sm:border-s-0",
          className,
        )}
        data-slot="sheet-popup"
        {...props}
      >
        {children}
        {showCloseButton && (
          <SheetPrimitive.Close
            aria-label="关闭"
            className="absolute end-2 top-2 inline-flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring"
            {...closeProps}
          >
            <XIcon aria-hidden size={18} />
          </SheetPrimitive.Close>
        )}
      </SheetPrimitive.Popup>
    </SheetPortal>
  );
}

export function SheetHeader({ className, ...props }: React.ComponentProps<"div">): React.ReactElement {
  return <div className={cn("flex flex-col gap-2 p-6 max-sm:pb-4", className)} data-slot="sheet-header" {...props} />;
}

export function SheetFooter({ className, ...props }: React.ComponentProps<"div">): React.ReactElement {
  return <div className={cn("flex flex-col-reverse gap-2 border-t bg-muted/72 px-6 py-4 sm:flex-row sm:justify-end", className)} data-slot="sheet-footer" {...props} />;
}

export function SheetTitle({ className, ...props }: SheetPrimitive.Title.Props): React.ReactElement {
  return <SheetPrimitive.Title className={cn("font-heading text-xl leading-none font-bold", className)} data-slot="sheet-title" {...props} />;
}

export function SheetDescription({ className, ...props }: SheetPrimitive.Description.Props): React.ReactElement {
  return <SheetPrimitive.Description className={cn("text-sm text-muted-foreground", className)} data-slot="sheet-description" {...props} />;
}

export function SheetPanel({ className, ...props }: React.ComponentProps<"div">): React.ReactElement {
  return <div className={cn("px-6 pb-6", className)} data-slot="sheet-panel" {...props} />;
}

export { SheetPrimitive };
